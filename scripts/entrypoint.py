import json
import logging
import logging.config
import os
import sys
import time

from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import get_random_chars
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.couchbase import CouchbaseClient

from settings import LOGGING_CONFIG

GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

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
        ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)
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

    def should_rotate(self):
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
        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warn("unable to find oxAuth config")
            return

        jks_pass = get_random_chars()
        jks_fn = self.manager.config.get("oxauth_openid_jks_fn")
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

        try:
            conf_webkeys = json.loads(config["oxAuthConfWebKeys"])
        except TypeError:  # not string/buffer
            conf_webkeys = config["oxAuthConfWebKeys"]
        except (KeyError, IndexError):
            conf_webkeys = {"keys": []}

        exp_hours = int(self.rotation_interval) + (conf_dynamic["idTokenLifetime"] / 3600)

        out, err, retcode = generate_openid_keys(jks_pass, jks_fn, jks_dn, exp=exp_hours)

        if retcode != 0 or err:
            logger.error("unable to generate keys; reason={}".format(err))
            return

        try:
            new_keys = json.loads(out)
            merged_webkeys = merge_keys(new_keys, conf_webkeys)

            logger.info("modifying oxAuth configuration")

            ox_modified = self.backend.modify_oxauth_config(
                config["id"],
                ox_rev + 1,
                conf_dynamic,
                merged_webkeys,
            )

            if all([ox_modified,
                    manager.secret.set("oxauth_jks_base64", encode_jks())]):
                manager.config.set("oxauth_key_rotated_at", int(time.time()))
                manager.secret.set("oxauth_openid_jks_pass", jks_pass)
                manager.secret.set(
                    "oxauth_openid_key_base64",
                    generate_base64_contents(json.dumps(merged_webkeys)),
                )
                logger.info("keys have been rotated")
        except (TypeError, ValueError) as exc:
            logger.warn("unable to get public keys; reason={}".format(exc))
        return True


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


def main():
    validate_rotation_check()
    validate_rotation_interval()

    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
    rotator = KeyRotator(manager, persistence_type, ldap_mapping, GLUU_KEY_ROTATION_INTERVAL)

    try:
        while True:
            logger.info("checking whether key should be rotated")

            try:
                if rotator.should_rotate():
                    rotator.rotate()
                else:
                    logger.info("no need to rotate keys at the moment")
            except Exception as exc:
                logger.warn("unable to rotate keys; reason={}".format(exc))
            time.sleep(int(GLUU_KEY_ROTATION_CHECK))
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


def merge_keys(new_keys, old_keys):
    """Merges new and old keys while omitting expired key.
    """
    now = int(time.time() * 1000)
    for key in old_keys["keys"]:
        if key.get("exp") > now:
            new_keys["keys"].append(key)
    return new_keys


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


if __name__ == "__main__":
    main()
