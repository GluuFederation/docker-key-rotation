# KeyRotation

A docker image to rotate oxAuth keys.

## Latest Stable Release

Latest stable release is `gluufederation/key-rotation:3.1.3_dev`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<INTERNAL-REV-VERSION>

For example, `gluufederation/key-rotation:3.1.3_dev` consists of:

- glufederation/key-rotation as `<IMAGE_NAME>`; the actual image name
- 3.1.3 as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- `dev` as `<INTERNAL-REV-VERSION>`; revision made when developing the image

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
- `GLUU_LDAP_URL`: URL to LDAP in `host:port` format string.
- `GLUU_KEY_ROTATION_INTERVAL`: Interval of key rotation (in days).
- `GLUU_KEY_ROTATION_CHECK`: Interval of rotation check (in seconds).

## Volumes

1. `/etc/certs` directory.

## Running The Container

Here's an example to run the container:

```
docker run -d \
    --name key-rotation \
    -e GLUU_KV_HOST=consul.example.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_URL=ldap.example.com:1636 \
    -e GLUU_KEY_ROTATION_INTERVAL=2 \
    gluufederation/key-rotation:3.1.3_dev
```
