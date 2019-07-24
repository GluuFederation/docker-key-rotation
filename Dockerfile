FROM openjdk:8-jre-alpine3.9

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============

RUN apk update && apk add --no-cache \
    openssl \
    py-pip \
    wget \
    shadow \
    git

# =============
# oxAuth client
# =============

ENV OX_VERSION=4.0.b1 \
    OX_BUILD_DATE=2019-07-23

# JAR files required to generate OpenID Connect keys
RUN mkdir -p /opt/key-rotation/javalibs \
    && wget -q https://ox.gluu.org/maven/org/gluu/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/key-rotation/javalibs/keygen.jar

# ====
# Tini
# ====

RUN wget -q https://github.com/krallin/tini/releases/download/v0.18.0/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======

COPY requirements.txt /tmp/requirements.txt
RUN pip install -U pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && apk del git

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER=consul \
    GLUU_CONFIG_CONSUL_HOST=localhost \
    GLUU_CONFIG_CONSUL_PORT=8500 \
    GLUU_CONFIG_CONSUL_CONSISTENCY=stale \
    GLUU_CONFIG_CONSUL_SCHEME=http \
    GLUU_CONFIG_CONSUL_VERIFY=false \
    GLUU_CONFIG_CONSUL_CACERT_FILE=/etc/certs/consul_ca.crt \
    GLUU_CONFIG_CONSUL_CERT_FILE=/etc/certs/consul_client.crt \
    GLUU_CONFIG_CONSUL_KEY_FILE=/etc/certs/consul_client.key \
    GLUU_CONFIG_CONSUL_TOKEN_FILE=/etc/certs/consul_token \
    GLUU_CONFIG_KUBERNETES_NAMESPACE=default \
    GLUU_CONFIG_KUBERNETES_CONFIGMAP=gluu \
    GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG=false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER=vault \
    GLUU_SECRET_VAULT_SCHEME=http \
    GLUU_SECRET_VAULT_HOST=localhost \
    GLUU_SECRET_VAULT_PORT=8200 \
    GLUU_SECRET_VAULT_VERIFY=false \
    GLUU_SECRET_VAULT_ROLE_ID_FILE=/etc/certs/vault_role_id \
    GLUU_SECRET_VAULT_SECRET_ID_FILE=/etc/certs/vault_secret_id \
    GLUU_SECRET_VAULT_CERT_FILE=/etc/certs/vault_client.crt \
    GLUU_SECRET_VAULT_KEY_FILE=/etc/certs/vault_client.key \
    GLUU_SECRET_VAULT_CACERT_FILE=/etc/certs/vault_ca.crt \
    GLUU_SECRET_KUBERNETES_NAMESPACE=default \
    GLUU_SECRET_KUBERNETES_SECRET=gluu \
    GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG=false

# ===============
# Persistence ENV
# ===============

# available options: couchbase, ldap, hybrid
# only takes affect when GLUU_PERSISTENCE_TYPE is hybrid
# available options: default, user, cache, site, statistic
ENV GLUU_PERSISTENCE_TYPE=ldap \
    GLUU_PERSISTENCE_LDAP_MAPPING=default \
    GLUU_COUCHBASE_URL=localhost \
    GLUU_LDAP_URL=localhost:1636

# ===========
# Generic ENV
# ===========

ENV GLUU_KEY_ROTATION_INTERVAL=48 \
    GLUU_KEY_ROTATION_CHECK=3600 \
    GLUU_WAIT_MAX_TIME=300 \
    GLUU_WAIT_SLEEP_DURATION=5

# ==========
# misc stuff
# ==========

WORKDIR /opt/key-rotation
RUN mkdir -p /etc/certs

COPY scripts /opt/key-rotation/scripts
RUN chmod +x /opt/key-rotation/scripts/entrypoint.sh

# # create gluu user
# RUN useradd -ms /bin/sh --uid 1000 gluu \
#     && usermod -a -G root gluu

# # adjust ownership
# RUN chown -R 1000:1000 /opt/key-rotation \
#     && chgrp -R 0 /opt/key-rotation && chmod -R g=u /opt/key-rotation \
#     && chgrp -R 0 /etc/certs && chmod -R g=u /etc/certs

# # run the entrypoint as gluu user
# USER 1000

ENTRYPOINT ["tini", "-g", "--"]
CMD ["/opt/key-rotation/scripts/entrypoint.sh"]
