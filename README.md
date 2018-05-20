# KeyRotation

A docker image to rotate oxAuth keys.

## Latest Stable Release

Latest stable release is `gluufederation/key-rotation:3.1.2_dev`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<BASELINE_DEV>

For example, `gluufederation/key-rotation:3.1.2_dev` consists of:

- `glufederation/key-rotation` as `<IMAGE_NAME>`; the actual image name
- `3.1.2` as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- `_dev` as `<BASELINE_DEV>`; used until official production release

## Installation

Pull the image:

    docker pull gluufederation/key-rotation:3.1.2_dev

## Environment Variables

- `GLUU_KV_HOST`: hostname or IP address of Consul.
- `GLUU_KV_PORT`: port of Consul.
- `GLUU_LDAP_URL`: URL to LDAP in `host:port` format string (i.e. `192.168.100.4:1636`); multiple URLs can be used using comma-separated value (i.e. `192.168.100.1:1636,192.168.100.2:1636`).
- `GLUU_KEY_ROTATION_INTERVAL`: Interval of key rotation check (in days).

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
    gluufederation/key-rotation:3.1.2_dev
```
