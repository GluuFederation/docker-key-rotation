FROM openjdk:8-jre-alpine3.9

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============

RUN apk update && apk add --no-cache \
    openssl \
    py-pip \
    wget \
    shadow

# =============
# oxAuth client
# =============

ENV OX_VERSION 4.0.0-SNAPSHOT
ENV OX_BUILD_DATE 2019-05-07

# JAR files required to generate OpenID Connect keys
RUN mkdir -p /opt/key-rotation/javalibs \
    && wget -q https://ox.gluu.org/maven/org/gluu/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/key-rotation/javalibs/keygen.jar

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======

RUN pip install -U pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONFIG_CONSUL_HOST localhost
ENV GLUU_CONFIG_CONSUL_PORT 8500
ENV GLUU_CONFIG_CONSUL_CONSISTENCY stale
ENV GLUU_CONFIG_CONSUL_SCHEME http
ENV GLUU_CONFIG_CONSUL_VERIFY false
ENV GLUU_CONFIG_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONFIG_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONFIG_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONFIG_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_CONFIG_KUBERNETES_NAMESPACE default
ENV GLUU_CONFIG_KUBERNETES_CONFIGMAP gluu
ENV GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER vault
ENV GLUU_SECRET_VAULT_SCHEME http
ENV GLUU_SECRET_VAULT_HOST localhost
ENV GLUU_SECRET_VAULT_PORT 8200
ENV GLUU_SECRET_VAULT_VERIFY false
ENV GLUU_SECRET_VAULT_ROLE_ID_FILE /etc/certs/vault_role_id
ENV GLUU_SECRET_VAULT_SECRET_ID_FILE /etc/certs/vault_secret_id
ENV GLUU_SECRET_VAULT_CERT_FILE /etc/certs/vault_client.crt
ENV GLUU_SECRET_VAULT_KEY_FILE /etc/certs/vault_client.key
ENV GLUU_SECRET_VAULT_CACERT_FILE /etc/certs/vault_ca.crt
ENV GLUU_SECRET_KUBERNETES_NAMESPACE default
ENV GLUU_SECRET_KUBERNETES_SECRET gluu
ENV GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG false

# ===========
# Generic ENV
# ===========

ENV GLUU_LDAP_URL localhost:1636
ENV GLUU_KEY_ROTATION_INTERVAL 48
ENV GLUU_KEY_ROTATION_CHECK 3600
ENV GLUU_WAIT_MAX_TIME 300
ENV GLUU_WAIT_SLEEP_DURATION 5

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
