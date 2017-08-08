# KeyRotation

A docker image to rotate oxAuth keys.

## Installation

Build the image:

```
docker build --rm --force-rm -t gluufederation/key-rotation:latest .
```

Or get it from Docker Hub:

```
docker pull gluufederation/key-rotation:latest
```

## Environment Variables

- `GLUU_KV_HOST`: hostname or IP address of Consul.
- `GLUU_KV_PORT`: port of Consul.
- `GLUU_LDAP_URL`: URL to LDAP in `host:port` format string (i.e. `192.168.100.4:1389`); multiple URLs can be used using comma-separated value (i.e. `192.168.100.1:1389,192.168.100.2:1389`).
- `GLUU_KEY_ROTATION_INTERVAL`: Interval of key rotation check (in days).

## Volumes

1. `/etc/certs` directory.

## Running The Container

Here's an example to run the container:

```
docker run -d \
    --name key-rotation \
    -e GLUU_KV_HOST=my.consul.domain.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_URL=my.ldap.domain.com:1389 \
    -e GLUU_KEY_ROTATION_INTERVAL=2 \
    gluufederation/key-rotation:containership
```

## TODO

* [x] Distribute `oxauth-keys.jks`
