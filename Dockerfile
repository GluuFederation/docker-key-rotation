FROM openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl

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

# ==========
# misc stuff
# ==========
WORKDIR /opt/key-rotation
RUN mkdir -p /etc/certs
VOLUME /etc/certs
ENV GLUU_LDAP_URL localhost:1636
ENV GLUU_KEY_ROTATION_INTERVAL 48
ENV GLUU_KEY_ROTATION_CHECK 3600

COPY entrypoint.py /opt/key-rotation/entrypoint.py
COPY wait-for-it /opt/key-rotation/wait-for-it
COPY gluu_config.py /opt/key-rotation/gluu_config.py
CMD ["/opt/key-rotation/wait-for-it", "python", "/opt/key-rotation/entrypoint.py"]
