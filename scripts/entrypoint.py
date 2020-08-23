"""
Entry point script that handles rotating oxAuth keys:
- oxAuth starts off using old/expired JWKS + JKS
- key-rotation re-generates new JWKS + JKS
- key-rotation creates a backup of old JKS and JWKS in oxAuth at /etc/certs/oxauth-keys.jks
  and /etc/certs/oxauth-keys.json. Note: At this point oxAuth is still using cached (old/expired) JWKS + JKS
- key-rotation pushes new JKS .Note: At this point oxAuth is still using cached (old/expired) JWKS + JKS
- key-rotation saves the JWKS in persistence:
  if the process fails key rotation restores the JSK from backup in oxauth
  if the process succeeds, oxAuth reloads itself hence loading new JWKS + JKS pair
"""
import json
import logging
import logging.config
import os
import sys
import time

import click
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
# from pygluu.containerlib.utils import get_random_chars
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.couchbase import CouchbaseClient
from pygluu.containerlib.meta import DockerMeta
from pygluu.containerlib.meta import KubernetesMeta

from settings import LOGGING_CONFIG

# Interval between rotation (in hours)
GLUU_KEY_ROTATION_INTERVAL = os.environ.get("GLUU_KEY_ROTATION_INTERVAL", 48)

# check interval (by default per 1 hour)
GLUU_KEY_ROTATION_CHECK = os.environ.get("GLUU_KEY_ROTATION_CHECK", 60 * 60)

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 RSA1_5 RSA-OAEP"
ENC_KEYS = SIG_KEYS


logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")

manager = get_manager()


class BaseBackend(object):
    def get_oxauth_config(self):
        raise NotImplementedError

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        raise NotImplementedError


class LDAPBackend(BaseBackend):
    def __init__(self, host, user, password):
        ldap_server = Server(host, port=1636, use_ssl=True)
        self.backend = Connection(ldap_server, user, password)

    def get_oxauth_config(self):
        # base DN for oxAuth config
        oxauth_base = ",".join([
            "ou=oxauth",
            "ou=configuration",
            "o=gluu",
        ])

        with self.backend as conn:
            conn.search(
                search_base=oxauth_base,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=[
                    "oxRevision",
                    "oxAuthConfWebKeys",
                    "oxAuthConfDynamic",
                ]
            )

            if not conn.entries:
                return {}

            entry = conn.entries[0]

            config = {
                "id": entry.entry_dn,
                "oxRevision": entry["oxRevision"][0],
                "oxAuthConfWebKeys": entry["oxAuthConfWebKeys"][0],
                "oxAuthConfDynamic": entry["oxAuthConfDynamic"][0],
            }
            return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        with self.backend as conn:
            conn.modify(id_, {
                'oxRevision': [(MODIFY_REPLACE, [str(ox_rev)])],
                'oxAuthConfWebKeys': [(MODIFY_REPLACE, [json.dumps(conf_webkeys)])],
                'oxAuthConfDynamic': [(MODIFY_REPLACE, [json.dumps(conf_dynamic)])],
            })

            result = conn.result["description"]
            return result == "success"


class CouchbaseBackend(BaseBackend):
    def __init__(self, host, user, password):
        self.backend = CouchbaseClient(host, user, password)

    def get_oxauth_config(self):
        req = self.backend.exec_query(
            "SELECT oxRevision, oxAuthConfDynamic, oxAuthConfWebKeys "
            "FROM `gluu` "
            "USE KEYS 'configuration_oxauth'",
        )
        if not req.ok:
            return {}

        config = req.json()["results"][0]

        if not config:
            return {}

        config.update({"id": "configuration_oxauth"})
        return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        req = self.backend.exec_query(
            "UPDATE `gluu` "
            "USE KEYS '{0}' "
            "SET oxRevision={1}, oxAuthConfDynamic={2}, oxAuthConfWebKeys={3} "
            "RETURNING oxRevision".format(
                id_, ox_rev, json.dumps(conf_dynamic), json.dumps(conf_webkeys),
            )
        )

        if not req.ok:
            return False
        return True


class KeyRotator(object):
    def __init__(self, manager, persistence_type, ldap_mapping="default",
                 rotation_interval=48):
        if persistence_type in ("ldap", "couchbase"):
            backend_type = persistence_type
        else:
            # persistence_type is hybrid
            if ldap_mapping == "default":
                backend_type = "ldap"
            else:
                backend_type = "couchbase"

        # resolve backend
        if backend_type == "ldap":
            host = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
            user = manager.config.get("ldap_binddn")
            password = decode_text(
                manager.secret.get("encoded_ox_ldap_pw"),
                manager.secret.get("encoded_salt"),
            )
            backend_cls = LDAPBackend
        else:
            host = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
            user = get_couchbase_user(manager)
            password = get_couchbase_password(manager)
            backend_cls = CouchbaseBackend

        self.backend = backend_cls(host, user, password)
        self.manager = manager
        self.rotation_interval = rotation_interval

        metadata = os.environ.get("GLUU_CONTAINER_METADATA", "docker")
        if metadata == "kubernetes":
            self.meta_client = KubernetesMeta()
        else:
            self.meta_client = DockerMeta()

    def should_rotate(self):
        force_rotate = as_boolean(os.environ.get("GLUU_KEY_ROTATION_FORCE", False))
        if force_rotate:
            logger.warn("key rotation is set to force mode")
            return True

        last_rotation = self.manager.config.get("oxauth_key_rotated_at")

        # keys are not rotated yet
        if not last_rotation:
            return True

        # when keys are supposed to be rotated
        next_rotation = int(last_rotation) + (60 * 60 * int(self.rotation_interval))

        # current timestamp
        now = int(time.time())

        # check if current timestamp surpassed expected rotation timestamp
        return now > next_rotation

    def rotate(self):
        if not self.should_rotate():
            # logger.info("no need to rotate keys at the moment")
            return

        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warn("unable to find oxAuth config")
            return

        jks_pass = self.manager.secret.get("oxauth_openid_jks_pass")
        jks_fn = "/etc/certs/oxauth-keys.jks"
        jwks_fn = "/etc/certs/oxauth-keys.json"
        jks_dn = r"{}".format(self.manager.config.get("default_openid_jks_dn_name"))

        ox_rev = int(config["oxRevision"])

        try:
            conf_dynamic = json.loads(config["oxAuthConfDynamic"])
        except TypeError:  # not string/buffer
            conf_dynamic = config["oxAuthConfDynamic"]

        if conf_dynamic["keyRegenerationEnabled"]:
            logger.warn("keyRegenerationEnabled config was set to true; "
                        "skipping proccess to avoid conflict with "
                        "builtin key rotation feature in oxAuth")
            return

        conf_dynamic.update({
            "keyRegenerationEnabled": False,  # always set to False
            "keyRegenerationInterval": int(self.rotation_interval),
            "webKeysStorage": "keystore",
            "keyStoreSecret": jks_pass,
        })

        # exp_hours = int(self.rotation_interval) + (conf_dynamic["idTokenLifetime"] / 3600)
        exp_hours = int(self.rotation_interval)

        # create JKS file; this needs to be pushed out to
        # config/secret backend and oxauth containers
        out, err, retcode = generate_openid_keys(jks_pass, jks_fn, jks_dn, exp=exp_hours)

        if retcode != 0 or err:
            logger.error("unable to generate keys; reason={}".format(err))
            return

        # create JWKS file; this needs to be pushed out to
        # config/secret backend and oxauth containers
        with open(jwks_fn, "w") as f:
            f.write(out.decode())

        oxauth_containers = self.meta_client.get_containers("APP_NAME=oxauth")
        if not oxauth_containers:
            logger.warn("Unable to find any oxAuth container; make sure "
                        "to deploy oxAuth and set APP_NAME=oxauth "
                        "label on container level")
            return

        for container in oxauth_containers:
            name = self.meta_client.get_container_name(container)

            logger.info("creating backup of {0}:/etc/certs/oxauth-keys.jks".format(name))
            self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.jks /etc/certs/oxauth-keys.jks.backup")
            logger.info("creating new {0}:/etc/certs/oxauth-keys.jks".format(name))
            self.meta_client.copy_to_container(container, jks_fn)

            logger.info("creating backup of {0}:/etc/certs/oxauth-keys.json".format(name))
            self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.json /etc/certs/oxauth-keys.json.backup")
            logger.info("creating new {0}:/etc/certs/oxauth-keys.json".format(name))
            self.meta_client.copy_to_container(container, jwks_fn)

        try:
            keys = json.loads(out)
            # keys = merge_keys(keys, conf_webkeys)

            logger.info("modifying oxAuth configuration")
            ox_modified = self.backend.modify_oxauth_config(
                config["id"],
                ox_rev + 1,
                conf_dynamic,
                keys,
            )

            if not ox_modified:
                # restore jks and jwks
                logger.warn("failed to modify oxAuth configuration")
                for container in oxauth_containers:
                    logger.info("restoring backup of {0}:/etc/certs/oxauth-keys.jks".format(name))
                    self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.jks.backup /etc/certs/oxauth-keys.jks")
                    logger.info("restoring backup of {0}:/etc/certs/oxauth-keys.json".format(name))
                    self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.json.backup /etc/certs/oxauth-keys.json")
                return

            # XXX: save jwks and jks to config and secret for later use?
            if manager.secret.set("oxauth_jks_base64", encode_jks(jks_fn)):
                manager.config.set("oxauth_key_rotated_at", int(time.time()))
                manager.secret.set("oxauth_openid_jks_pass", jks_pass)
                # jwks
                manager.secret.set(
                    "oxauth_openid_key_base64",
                    generate_base64_contents(json.dumps(keys)),
                )
            logger.info("keys have been rotated")
        except (TypeError, ValueError) as exc:
            logger.warn("unable to get public keys; reason={}".format(exc))

    def disable_builtin(self):
        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warn("unable to find oxAuth config")
            return

        ox_rev = int(config["oxRevision"])

        try:
            conf_dynamic = json.loads(config["oxAuthConfDynamic"])
        except TypeError:  # not string/buffer
            conf_dynamic = config["oxAuthConfDynamic"]

        if not conf_dynamic["keyRegenerationEnabled"]:
            logger.info("the builtin oxAuth key-rotation has been disabled")
            return

        logger.warn("keyRegenerationEnabled config was set to true; "
                    "disabling the value to avoid conflict")

        conf_dynamic.update({
            "keyRegenerationEnabled": False,  # always set to False
        })

        try:
            keys = json.loads(config["oxAuthConfWebKeys"])
        except TypeError:  # not string/buffer
            keys = config["oxAuthConfWebKeys"]
        except (KeyError, IndexError):
            keys = {"keys": []}

        try:
            logger.info("modifying oxAuth configuration")
            ox_modified = self.backend.modify_oxauth_config(
                config["id"],
                ox_rev + 1,
                conf_dynamic,
                keys,
            )
            if ox_modified:
                logger.info("builtin oxAuth key-rotation has been disabled")
        except (TypeError, ValueError) as exc:
            logger.warn("unable to disable builtin oxAuth key-rotation; "
                        "reason={}".format(exc))


def generate_openid_keys(passwd, jks_path, dn, exp=365):
    if os.path.isfile(jks_path):
        os.unlink(jks_path)

    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-jar", "/app/javalibs/oxauth-client.jar",
        "-enc_keys", ENC_KEYS,
        "-sig_keys", SIG_KEYS,
        "-dnname", "{!r}".format(dn),
        "-expiration_hours", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])
    return exec_cmd(cmd)


def encode_jks(jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encode_text(fd.read(), manager.secret.get("encoded_salt"))
    return encoded_jks


# def merge_keys(new_keys, old_keys):
#     """Merges new and old keys while omitting expired key.
#     """
#     now = int(time.time() * 1000)
#     for key in old_keys["keys"]:
#         if key.get("exp") > now:
#             new_keys["keys"].append(key)
#     return new_keys


def validate_rotation_check():
    err = "GLUU_KEY_ROTATION_CHECK must use a valid integer greater than 0"
    try:
        if int(GLUU_KEY_ROTATION_CHECK) < 1:
            logger.error(err)
            sys.exit(1)
    except ValueError:
        logger.error(err)
        sys.exit(1)


def validate_rotation_interval():
    err = "GLUU_KEY_ROTATION_INTERVAL must use a valid integer greater than 0"
    try:
        if int(GLUU_KEY_ROTATION_INTERVAL) < 1:
            logger.error(err)
            sys.exit(1)
    except ValueError:
        logger.error(err)
        sys.exit(1)


@click.group()
def cli():
    pass


@cli.command()
def rotate():
    """Rotate keys.
    """
    validate_rotation_check()
    validate_rotation_interval()

    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
    rotator = KeyRotator(manager, persistence_type, ldap_mapping, GLUU_KEY_ROTATION_INTERVAL)

    try:
        while True:
            # logger.info("checking whether key should be rotated")
            try:
                rotator.rotate()
            except Exception as exc:
                logger.warn("unable to rotate keys; reason={}".format(exc))
            time.sleep(int(GLUU_KEY_ROTATION_CHECK))
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


@cli.command("disable-builtin")
def disable_builtin():
    """Disable builtin oxAuth key-rotation feature.
    """
    validate_rotation_check()
    validate_rotation_interval()

    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
    rotator = KeyRotator(manager, persistence_type, ldap_mapping, GLUU_KEY_ROTATION_INTERVAL)

    try:
        while True:
            # logger.info("checking whether builtin oxAuth key-rotation is enabled")
            try:
                rotator.disable_builtin()
            except Exception as exc:
                logger.warn("unable to disable builtin oxAuth key-rotation; "
                            "reason={}".format(exc))
            time.sleep(30)
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


if __name__ == "__main__":
    cli()
