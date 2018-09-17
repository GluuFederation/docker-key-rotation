FROM gluufederation/base-openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl \
    wget

# =============
# oxAuth client
# =============
ENV OX_VERSION 3.1.3.Final
ENV OX_BUILD_DATE 2018-04-30
# JAR files required to generate OpenID Connect keys
RUN mkdir -p /opt/key-rotation/javalibs \
    && wget -q https://ox.gluu.org/maven/org/xdi/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/key-rotation/javalibs/keygen.jar

# ======
# Python
# ======
RUN pip install -U pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ==========
# misc stuff
# ==========
WORKDIR /opt/key-rotation
RUN mkdir -p /etc/certs
VOLUME /etc/certs

ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONSUL_HOST localhost
ENV GLUU_CONSUL_PORT 8500
ENV GLUU_CONSUL_CONSISTENCY stale
ENV GLUU_CONSUL_SCHEME http
ENV GLUU_CONSUL_VERIFY false
ENV GLUU_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_KUBERNETES_NAMESPACE default
ENV GLUU_KUBERNETES_CONFIGMAP gluu
ENV GLUU_LDAP_URL localhost:1636
ENV GLUU_KEY_ROTATION_INTERVAL 48
ENV GLUU_KEY_ROTATION_CHECK 3600

COPY entrypoint.py /opt/key-rotation/entrypoint.py
COPY wait-for-it /opt/key-rotation/wait-for-it
COPY gluu_config.py /opt/key-rotation/gluu_config.py
ENTRYPOINT ["tini", "--"]
CMD ["/opt/key-rotation/wait-for-it", "python", "/opt/key-rotation/entrypoint.py"]
