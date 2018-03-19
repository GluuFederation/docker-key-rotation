import base64
import json
import logging
import os
import shlex
import subprocess
import time

import consulate
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE
from ldap3.core.exceptions import LDAPSocketOpenError
from M2Crypto.EVP import Cipher
from requests.exceptions import ConnectionError

GLUU_KV_HOST = os.environ.get("GLUU_KV_HOST", "localhost")
GLUU_KV_PORT = os.environ.get("GLUU_KV_PORT", 8500)
GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

# Interval between rotation (in hours)
GLUU_KEY_ROTATION_INTERVAL = os.environ.get("GLUU_KEY_ROTATION_INTERVAL", 48)

# check interval (by default per 1 hour)
GLUU_KEY_ROTATION_CHECK = os.environ.get("GLUU_KEY_ROTATION_CHECK", 60 * 60)

consul = consulate.Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)

logger = logging.getLogger("key_rotation")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


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
    last_rotation = consul.kv.get("oxauth_key_rotated_at")

    # keys are not rotated yet
    if not last_rotation:
        return True

    # ensure rotation interval is an integer
    try:
        rotation_interval = int(GLUU_KEY_ROTATION_INTERVAL)
    except ValueError:
        rotation_interval = 48

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
    # Porting from pyDes-based encryption (see http://git.io/htpk)
    # to use M2Crypto instead (see https://gist.github.com/mrluanma/917014)
    cipher = Cipher(alg="des_ede3_ecb",
                    key=b"{}".format(key),
                    op=0,
                    iv="\0" * 16)
    decrypted_text = cipher.update(base64.b64decode(
        b"{}".format(encrypted_text)
    ))
    decrypted_text += cipher.final()
    return decrypted_text


def get_ldap_servers():
    servers = []
    for server in GLUU_LDAP_URL.split(","):
        host, port = server.split(":", 1)
        servers.append({"host": host, "port": port})
    return servers


def modify_oxauth_config(pub_keys):
    # user = "cn=directory manager,o=gluu"
    user = "cn=directory manager"
    passwd = decrypt_text(consul.kv.get("encoded_ox_ldap_pw"),
                          consul.kv.get("encoded_salt"))

    # base DN for oxAuth config
    oxauth_base = ",".join([
        "ou=oxauth",
        "ou=configuration",
        "inum={}".format(consul.kv.get("inumAppliance")),
        "ou=appliances",
        "o=gluu",
    ])

    for server in get_ldap_servers():
        try:
            ldap_server = Server(server["host"], port=int(server["port"]), use_ssl=True)
            logger.info("connecting to server {}:{}".format(server["host"], server["port"]))

            with Connection(ldap_server, user, passwd) as conn:
                conn.search(search_base=oxauth_base, search_filter="(objectClass=*)",
                            search_scope=BASE, attributes=['*'])

                if not conn.entries:
                    # search failed due to missing entry
                    logger.warn("unable to find oxAuth config")
                    continue

                entry = conn.entries[0]

                # oxRevision is increased to mark update
                ox_rev = str(int(entry["oxRevision"][0]) + 1)

                # update public keys if necessary
                keys_conf = json.loads(entry["oxAuthConfWebKeys"][0])
                keys_conf["keys"] = pub_keys
                serialized_keys_conf = json.dumps(keys_conf)

                dyn_conf = json.loads(entry["oxAuthConfDynamic"][0])
                dyn_conf.update({
                    "keyRegenerationEnabled": False,  # always set to False
                    "keyRegenerationInterval": int(GLUU_KEY_ROTATION_INTERVAL),
                    "defaultSignatureAlgorithm": "RS512",
                })
                dyn_conf.update({
                    "webKeysStorage": "keystore",
                    "keyStoreSecret": consul.kv.get("oxauth_openid_jks_pass"),
                })
                serialized_dyn_conf = json.dumps(dyn_conf)

                # update the attributes
                logger.info("modifying oxAuth configuration")
                conn.modify(entry.entry_dn, {
                    'oxRevision': [(MODIFY_REPLACE, [ox_rev])],
                    'oxAuthConfWebKeys': [(MODIFY_REPLACE, [serialized_keys_conf])],
                    'oxAuthConfDynamic': [(MODIFY_REPLACE, [serialized_dyn_conf])],
                })

                result = conn.result["description"]
                return result == "success"
        except LDAPSocketOpenError as exc:
            logger.warn("Unable to connect to LDAP at {}:{}; reason={}".format(
                server["host"], server["port"], exc))
            logger.info("Trying other server (if possible).")
            continue

    # mark update as failed
    return False


def encode_jks(jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encrypt_text(fd.read(), consul.kv.get("encoded_salt"))
    return encoded_jks


def rotate_keys():
    out, err, retcode = generate_openid_keys(
        consul.kv.get("oxauth_openid_jks_pass"),
        consul.kv.get("oxauth_openid_jks_fn"),
        r"{}".format(consul.kv.get("default_openid_jks_dn_name")),
    )

    if retcode != 0:
        logger.error("unable to generate keys; reason={}".format(err))
        return False

    try:
        pub_keys = json.loads(out).get("keys")
    except (TypeError, ValueError) as exc:
        logger.warn("unable to get public keys; reason={}".format(exc))
        return False

    if modify_oxauth_config(pub_keys):
        consul.kv.set("oxauth_key_rotated_at", int(time.time()))
        consul.kv.set("oxauth_jks_base64", encode_jks())
        logger.info("keys have been rotated")
        return True

    # mark rotation as failed
    return False


def main():
    try:
        check_interval = int(GLUU_KEY_ROTATION_CHECK)
    except ValueError:
        check_interval = 60 * 60

    try:
        while True:
            logger.info("checking whether key should be rotated")

            try:
                if should_rotate_keys():
                    rotate_keys()
                else:
                    logger.info("no need to rotate keys at the moment")
            except ConnectionError as exc:
                logger.warn("unable to connect to KV storage; reason={}".format(exc))
            time.sleep(check_interval)
    except KeyboardInterrupt:
        logger.warn("canceled by user; exiting ...")


def encrypt_text(text, key):
    # Porting from pyDes-based encryption (see http://git.io/htxa)
    # to use M2Crypto instead (see https://gist.github.com/mrluanma/917014)
    cipher = Cipher(alg="des_ede3_ecb",
                    key=b"{}".format(key),
                    op=1,
                    iv="\0" * 16)
    encrypted_text = cipher.update(b"{}".format(text))
    encrypted_text += cipher.final()
    return base64.b64encode(encrypted_text)


if __name__ == "__main__":
    main()
