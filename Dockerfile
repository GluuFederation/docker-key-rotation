FROM ubuntu:14.04

MAINTAINER Gluu Inc. <support@gluu.org>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --force-yes \
    python \
    python-dev \
    python-pip \
    openjdk-7-jre-headless \
    wget \
    libldap2-dev \
    libsasl2-dev \
    swig \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION 3.1.0-SNAPSHOT
RUN mkdir -p /opt/key-rotation/javalibs
RUN wget -q http://ox.gluu.org/maven/org/xdi/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/key-rotation/javalibs/keygen.jar

# ====
# tini
# ====

ENV TINI_VERSION v0.15.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini -O /tini \
    && chmod +x /tini
ENTRYPOINT ["/tini", "--"]

# ====
# gosu
# ====

ENV GOSU_VERSION 1.10
RUN wget -q https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-amd64 -O /usr/local/bin/gosu \
    && chmod +x /usr/local/bin/gosu

# ======
# Python
# ======
WORKDIR /opt/key-rotation

RUN pip install -U pip

# A workaround to address https://github.com/docker/docker-py/issues/1054
# and to make sure latest pip is being used, not from OS one
ENV PYTHONPATH="/usr/local/lib/python2.7/dist-packages:/usr/lib/python2.7/dist-packages"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ====
# cron
# ====

# Add crontab file in the cron directory
COPY cron/key-rotation /etc/cron.d/

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/key-rotation

# Create the log file to be able to run tail
RUN touch /var/log/key-rotation.log

# ==========
# misc stuff
# ==========

RUN mkdir -p /etc/certs

VOLUME /etc/certs

ENV GLUU_KV_HOST localhost
ENV GLUU_KV_PORT 8500
ENV GLUU_LDAP_URL localhost:8500
ENV GLUU_KEY_ROTATION_INTERVAL 2

COPY entrypoint.py ./
COPY entrypoint.sh ./

RUN chmod +x /opt/key-rotation/entrypoint.sh

CMD ["/opt/key-rotation/entrypoint.sh"]
