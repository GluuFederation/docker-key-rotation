# KeyRotation

A docker image to rotate oxAuth keys.

## Latest Stable Release

Latest stable release is `gluufederation/key-rotation:3.1.3_02`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<RELEASE_VERSION>

For example, `gluufederation/config-init:3.1.3_02` consists of:

- `glufederation/config-init` as `<IMAGE_NAME>`; the actual image name
- `3.1.3` as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- `02` as `<RELEASE_VERSION>`

## Installation

Pull the image:

    docker pull gluufederation/key-rotation:3.1.3_02

## Environment Variables

- `GLUU_LDAP_URL`: URL to LDAP in `host:port` format string.
- `GLUU_KEY_ROTATION_INTERVAL`: Interval of key rotation (in days).
- `GLUU_KEY_ROTATION_CHECK`: Interval of rotation check (in seconds).
- `GLUU_CONFIG_ADAPTER`: config backend (either `consul` for Consul KV or `kubernetes` for Kubernetes configmap)

The following environment variables are activated only if `GLUU_CONFIG_ADAPTER` is set to `consul`:

- `GLUU_CONSUL_HOST`: hostname or IP of Consul (default to `localhost`)
- `GLUU_CONSUL_PORT`: port of Consul (default to `8500`)
- `GLUU_CONSUL_CONSISTENCY`: Consul consistency mode (choose one of `default`, `consistent`, or `stale`). Default to `stale` mode.

otherwise, if `GLUU_CONFIG_ADAPTER` is set to `kubernetes`:

- `GLUU_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`)
- `GLUU_KUBERNETES_CONFIGMAP`: Kubernetes configmap name (default to `gluu`)

## Volumes

1. `/etc/certs` directory.

## Running The Container

Here's an example to run the container:

```
docker run -d \
    --name key-rotation \
    -e GLUU_CONSUL_HOST=consul.example.com \
    -e GLUU_LDAP_URL=ldap.example.com:1636 \
    -e GLUU_KEY_ROTATION_INTERVAL=2 \
    gluufederation/key-rotation:3.1.3_02
```
