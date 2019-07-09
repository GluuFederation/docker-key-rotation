import base64
import json
import logging
import os
import random
import shlex
import string
import subprocess
import sys
import time

import pyDes
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE
# from ldap3.core.exceptions import LDAPSocketOpenError

from cbm import CBM
from gluulib import get_manager

GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

# Interval between rotation (in hours)
GLUU_KEY_ROTATION_INTERVAL = os.environ.get("GLUU_KEY_ROTATION_INTERVAL", 48)

# check interval (by default per 1 hour)
GLUU_KEY_ROTATION_CHECK = os.environ.get("GLUU_KEY_ROTATION_CHECK", 60 * 60)

# Default charset
_DEFAULT_CHARS = "".join([string.ascii_uppercase,
                          string.digits,
                          string.lowercase])

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512"
ENC_KEYS = "RSA_OAEP RSA1_5"


logger = logging.getLogger("key_rotation")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

manager = get_manager()


def exec_cmd(cmd):
    args = shlex.split(cmd)
    popen = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    retcode = popen.returncode
    return stdout, stderr, retcode


def generate_openid_keys(passwd, jks_path, dn, exp=365):
    cmd = " ".join([
        "java",
        "-jar", "/opt/key-rotation/javalibs/keygen.jar",
        "-enc_keys", ENC_KEYS,
        "-sig_keys", SIG_KEYS,
        "-dnname", "{!r}".format(dn),
        "-expiration_hours", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])

    out, err, retcode = exec_cmd(cmd)
    return out, err, retcode


def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def encode_jks(jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encrypt_text(fd.read(), manager.secret.get("encoded_salt"))
    return encoded_jks


# def rotate_keys(user, passwd, jks_pass, jks_fn, jks_dn):
#     try:
#         logger.info("connecting to server {}".format(GLUU_LDAP_URL))

#         ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)

#         with Connection(ldap_server, user, passwd) as conn:
#             # get oxAuth config from LDAP
#             ox_config = get_oxauth_config(conn)

#             if not ox_config:
#                 # search failed due to missing entry
#                 logger.warn("unable to find oxAuth config")
#                 return

#             ox_rev = int(ox_config["oxRevision"][0])

#             conf_dynamic = json.loads(ox_config["oxAuthConfDynamic"][0])

#             if conf_dynamic["keyRegenerationEnabled"]:
#                 logger.warn("keyRegenerationEnabled config was set to true; "
#                             "skipping proccess to avoid conflict with "
#                             "builtin key rotation feature in oxAuth")
#                 return

#             conf_dynamic.update({
#                 "keyRegenerationEnabled": False,  # always set to False
#                 "keyRegenerationInterval": int(GLUU_KEY_ROTATION_INTERVAL),
#                 "webKeysStorage": "keystore",
#                 "keyStoreSecret": jks_pass,
#             })

#             try:
#                 conf_webkeys = json.loads(ox_config["oxAuthConfWebKeys"][0])
#             except IndexError:
#                 conf_webkeys = {"keys": []}

#             exp_hours = int(GLUU_KEY_ROTATION_INTERVAL) + (conf_dynamic["idTokenLifetime"] / 3600)

#             out, err, retcode = generate_openid_keys(
#                 jks_pass, jks_fn, jks_dn, exp=exp_hours)

#             if retcode != 0:
#                 logger.error("unable to generate keys; reason={}".format(err))
#                 return

#             try:
#                 new_keys = json.loads(out)
#                 merged_webkeys = merge_keys(new_keys, conf_webkeys)
#                 ox_modified = modify_oxauth_config(
#                     conn, ox_config.entry_dn, ox_rev, conf_dynamic, merged_webkeys)

#                 if all([ox_modified,
#                         manager.secret.set("oxauth_jks_base64", encode_jks())]):
#                     manager.config.set("oxauth_key_rotated_at", int(time.time()))
#                     logger.info("keys have been rotated")
#             except (TypeError, ValueError) as exc:
#                 logger.warn("unable to get public keys; reason={}".format(exc))
#     # cant connect to LDAP
#     except LDAPSocketOpenError as exc:
#         logger.warn("Unable to connect to LDAP at {}; reason={}".format(
#             GLUU_LDAP_URL, exc))


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
                logger.warn("unable to connect to config backend; "
                            "reason={}".format(exc))
            time.sleep(int(GLUU_KEY_ROTATION_CHECK))
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


def encrypt_text(text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = cipher.encrypt(b"{}".format(text))
    return base64.b64encode(encrypted_text)


def get_random_chars(size=12, chars=_DEFAULT_CHARS):
    """Generates random characters.
    """
    return ''.join(random.choice(chars) for _ in range(size))


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
            password = decrypt_text(
                manager.secret.get("encoded_ox_ldap_pw"),
                manager.secret.get("encoded_salt"),
            )
            backend_cls = LDAPBackend
        else:
            host = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
            user = manager.config.get("couchbase_server_user")
            password = decrypt_text(
                manager.secret.get("encoded_couchbase_server_pw"),
                manager.secret.get("encoded_salt"),
            )
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

        conf_dynamic = json.loads(config["oxAuthConfDynamic"])

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
        except IndexError:
            conf_webkeys = {"keys": []}

        exp_hours = int(self.rotation_interval) + (conf_dynamic["idTokenLifetime"] / 3600)

        out, err, retcode = generate_openid_keys(jks_pass, jks_fn, jks_dn, exp=exp_hours)

        if retcode != 0:
            logger.error("unable to generate keys; reason={}".format(err))
            return

        try:
            new_keys = json.loads(out)
            merged_webkeys = merge_keys(new_keys, conf_webkeys)

            logger.info("modifying oxAuth configuration")
            ox_modified = self.backend.modify_oxauth_config(
                config["id"], ox_rev, conf_dynamic, merged_webkeys,
            )

            if all([ox_modified,
                    manager.secret.set("oxauth_jks_base64", encode_jks())]):
                manager.config.set("oxauth_key_rotated_at", int(time.time()))
                logger.info("keys have been rotated")
        except (TypeError, ValueError) as exc:
            logger.warn("unable to get public keys; reason={}".format(exc))


class LDAPBackend(object):
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
        serialized_keys_conf = json.dumps(conf_webkeys)
        serialized_dyn_conf = json.dumps(conf_dynamic)
        ox_rev = str(ox_rev + 1)

        with self.backend as conn:
            conn.modify(id_, {
                'oxRevision': [(MODIFY_REPLACE, [ox_rev])],
                'oxAuthConfWebKeys': [(MODIFY_REPLACE, [serialized_keys_conf])],
                'oxAuthConfDynamic': [(MODIFY_REPLACE, [serialized_dyn_conf])],
            })

            result = conn.result["description"]
            return result == "success"


class CouchbaseBackend(object):
    def __init__(self, host, user, password):
        self.backend = CBM(host, user, password)

    def get_oxauth_config(self):
        req = self.backend.exec_query(
            "SELECT oxRevision, oxAuthConfDynamic, oxAuthConfWebKeys "
            "FROM `gluu` "
            "USE KEYS ['configuration_oxauth']",
        )
        if not req.ok:
            return {}

        config = req.json()["results"][0]

        if not config:
            return {}

        config.update({"id": "configuration_oxauth"})
        return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        serialized_keys_conf = json.dumps(conf_webkeys)
        serialized_dyn_conf = json.dumps(conf_dynamic)
        ox_rev = str(ox_rev + 1)

        req = self.backend.exec_query(
            "UPDATE `gluu` "
            "USE KEYS '{0}' "
            "SET oxRevision='{1}', oxAuthConfDynamic='{2}', oxAuthConfWebKeys={3} "
            "RETURNING oxRevision".format(
                id_, ox_rev, serialized_dyn_conf, serialized_keys_conf,
            )
        )

        if not req.ok:
            return False
        return True


if __name__ == "__main__":
    main()
