import base64
import json
import logging
import os
import random
import shlex
import string
import subprocess
import time

import pyDes
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE
from ldap3.core.exceptions import LDAPSocketOpenError

from gluu_config import ConfigManager

GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

# Interval between rotation (in hours)
GLUU_KEY_ROTATION_INTERVAL = os.environ.get("GLUU_KEY_ROTATION_INTERVAL", 48)

# check interval (by default per 1 hour)
GLUU_KEY_ROTATION_CHECK = os.environ.get("GLUU_KEY_ROTATION_CHECK", 60 * 60)

# Default charset
_DEFAULT_CHARS = "".join([string.ascii_uppercase,
                          string.digits,
                          string.lowercase])


logger = logging.getLogger("key_rotation")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

config_manager = ConfigManager()


def exec_cmd(cmd):
    args = shlex.split(cmd)
    popen = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    retcode = popen.returncode
    return stdout, stderr, retcode


def generate_openid_keys(passwd, jks_path, dn, exp=365,
                         alg="RS256 RS384 RS512 ES256 ES384 ES512"):
    cmd = " ".join([
        "java",
        "-jar", "/opt/key-rotation/javalibs/keygen.jar",
        "-enc_keys", alg,
        "-sig_keys", alg,
        "-dnname", "{!r}".format(dn),
        "-expiration", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])

    out, err, retcode = exec_cmd(cmd)
    return out, err, retcode


def should_rotate_keys():
    last_rotation = config_manager.get("oxauth_key_rotated_at")

    # keys are not rotated yet
    if not last_rotation:
        return True

    # ensure rotation interval is an integer
    try:
        rotation_interval = int(GLUU_KEY_ROTATION_INTERVAL)
    except ValueError:
        rotation_interval = 48

    # due to the limitation on KeyGenerator CLI where expiration
    # is set to daily, ensure interval always a multiplication of 24 (hours)
    if rotation_interval % 24 != 0:
        logger.warn("GLUU_KEY_ROTATION_INTERVAL value only support "
                    "a value of multiplication of 24")
        return False

    # use default rotation interval if the number is less than equal 0
    if rotation_interval <= 0:
        rotation_interval = 48

    # when keys are supposed to be rotated
    next_rotation = int(last_rotation) + (60 * 60 * rotation_interval)

    # current timestamp
    now = int(time.time())

    # check if current timestamp surpassed expected rotation timestamp
    return now > next_rotation


def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def modify_oxauth_config(ldap_conn, entry_dn, ox_rev, conf_dynamic, conf_webkeys):
    logger.info("modifying oxAuth configuration")

    serialized_keys_conf = json.dumps(conf_webkeys)
    serialized_dyn_conf = json.dumps(conf_dynamic)
    ox_rev = str(ox_rev + 1)

    ldap_conn.modify(entry_dn, {
        'oxRevision': [(MODIFY_REPLACE, [ox_rev])],
        'oxAuthConfWebKeys': [(MODIFY_REPLACE, [serialized_keys_conf])],
        'oxAuthConfDynamic': [(MODIFY_REPLACE, [serialized_dyn_conf])],
    })

    result = ldap_conn.result["description"]
    return result == "success"


def encode_jks(jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encrypt_text(fd.read(), config_manager.get("encoded_salt"))
    return encoded_jks


def rotate_keys(user, passwd, inum, jks_pass, jks_fn, jks_dn):
    try:
        logger.info("connecting to server {}".format(GLUU_LDAP_URL))

        ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)

        with Connection(ldap_server, user, passwd) as conn:
            # get oxAuth config from LDAP
            ox_config = get_oxauth_config(conn, inum)

            if not ox_config:
                # search failed due to missing entry
                logger.warn("unable to find oxAuth config")
                return

            ox_rev = int(ox_config["oxRevision"][0])

            conf_dynamic = json.loads(ox_config["oxAuthConfDynamic"][0])

            if conf_dynamic["keyRegenerationEnabled"]:
                logger.warn("keyRegenerationEnabled config was set to true; "
                            "skipping proccess to avoid conflict with "
                            "builtin key rotation feature in oxAuth")
                return

            conf_dynamic.update({
                "keyRegenerationEnabled": False,  # always set to False
                "keyRegenerationInterval": int(GLUU_KEY_ROTATION_INTERVAL),
                "webKeysStorage": "keystore",
                "keyStoreSecret": jks_pass,
                # "defaultSignatureAlgorithm": "RS512",
            })

            conf_webkeys = json.loads(ox_config["oxAuthConfWebKeys"][0])

            exp_in_days = get_exp_in_days(
                int(GLUU_KEY_ROTATION_INTERVAL),
                conf_dynamic["idTokenLifetime"],
            )

            out, err, retcode = generate_openid_keys(
                jks_pass, jks_fn, jks_dn, exp=exp_in_days)

            if retcode != 0:
                logger.error("unable to generate keys; reason={}".format(err))
                return False

            try:
                new_keys = json.loads(out)
                conf_webkeys = merge_keys(new_keys, conf_webkeys)
                # conf_webkeys = new_keys
                ox_modified = modify_oxauth_config(
                    conn, ox_config.entry_dn, ox_rev, conf_dynamic, conf_webkeys)

                if all([ox_modified,
                        config_manager.set("oxauth_jks_base64", encode_jks())]):
                    config_manager.set("oxauth_key_rotated_at", int(time.time()))
                    logger.info("keys have been rotated")
                    return True
            except (TypeError, ValueError) as exc:
                logger.warn("unable to get public keys; reason={}".format(exc))
                return False
    # cant connect to LDAP
    except LDAPSocketOpenError as exc:
        logger.warn("Unable to connect to LDAP at {}; reason={}".format(
            GLUU_LDAP_URL, exc))

    # mark rotation as failed
    return False


def main():
    inum = config_manager.get("inumAppliance")
    user = config_manager.get("ldap_binddn")
    passwd = decrypt_text(config_manager.get("encoded_ox_ldap_pw"),
                          config_manager.get("encoded_salt"))
    # jks_pass = config_manager.get("oxauth_openid_jks_pass")
    jks_pass = get_random_chars()
    jks_fn = config_manager.get("oxauth_openid_jks_fn")
    jks_dn = r"{}".format(config_manager.get("default_openid_jks_dn_name"))

    try:
        check_interval = int(GLUU_KEY_ROTATION_CHECK)
    except ValueError:
        check_interval = 60 * 60

    try:
        while True:
            logger.info("checking whether key should be rotated")

            try:
                if should_rotate_keys():
                    rotate_keys(user, passwd, inum, jks_pass, jks_fn, jks_dn)
                else:
                    logger.info("no need to rotate keys at the moment")
            except Exception as exc:
                logger.warn("unable to connect to config backend; reason={}".format(exc))
            time.sleep(check_interval)
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


def encrypt_text(text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = cipher.encrypt(b"{}".format(text))
    return base64.b64encode(encrypted_text)


def get_exp_in_days(rotation_interval, token_lifetime):
    # current version of KeyGenerator CLI only accept `--expiration=<days>`
    days = (rotation_interval + (token_lifetime / 3600)) / 24
    # TODO: `days` value might be 0, do we need to set fallback or leave it as is?
    return days


def get_random_chars(size=12, chars=_DEFAULT_CHARS):
    """Generates random characters.
    """
    return ''.join(random.choice(chars) for _ in range(size))


def get_oxauth_config(conn, inum):
    # base DN for oxAuth config
    oxauth_base = ",".join([
        "ou=oxauth",
        "ou=configuration",
        "inum={}".format(inum),
        "ou=appliances",
        "o=gluu",
    ])

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
        return
    return conn.entries[0]


def merge_keys(new_keys, old_keys):
    """Merges new and old keys while omitting expired key.
    """
    now = int(time.time() * 1000)
    for key in old_keys["keys"]:
        if key.get("exp") > now:
            new_keys["keys"].append(key)
    return new_keys


if __name__ == "__main__":
    main()