# Changelog

Here you can see an overview of changes between each release.

## Version 3.1.5_04

Released on May 10th, 2019.

* Alpine upgraded to v3.9. Ref: https://github.com/GluuFederation/gluu-docker/issues/71.

## Version 3.1.5_03

Released on April 23rd, 2019.

* Fixed usage on KeyGenerator CLI call. Issue: https://github.com/GluuFederation/docker-key-rotation/issues/4.

## Version 3.1.5_02

Released on April 9th, 2019.

* Added license info on container startup.

## Version 3.1.5_01

Released on March 23rd, 2019.

* Upgraded to Gluu Server 3.1.5.

## Version 3.1.4_02

Released on March 15th, 2019.

* Fixed issue where `oxauth_key_rotated_at` is saved even when `oxauth_jks_base64` config couldn't be saved.

## Version 3.1.4_01

Released on November 12th, 2018.

* Upgraded to Gluu Server 3.1.4.

## Version 3.1.3_05

Released on September 18th, 2018.

* Changed base image to use Alpine 3.8.1.

## Version 3.1.3_04

Released on September 12th, 2018.

* Added feature to connect to secure Consul (HTTPS).

## Version 3.1.3_03

Released on August 31st, 2018.

* Added Tini to handle signal forwarding and reaping zombie processes.

## Version 3.1.3_02

Released on July 20th, 2018.

* Added wrapper to manage config via Consul KV or Kubernetes configmap.

## Version 3.1.3_01

Released on June 12th, 2018.

* Upgraded to Gluu Server 3.1.3

## Version 3.1.2_01

Released on June 12th, 2018.

* Upgraded to Gluu Server 3.1.2

## Version 3.1.1_rev1.0.0-beta2

Released on October 11th, 2017.

* Use latest oxauth-client build.

## Version 3.1.1_rev1.0.0-beta1

Released on October 6th, 2017.

* Migrated to Gluu Server 3.1.1.

## Version 3.0.1_rev1.0.0-beta2

Released on August 16th, 2017.

* Fixed base64 string when rotating keys.

## Version 3.0.1_rev1.0.0-beta1

Released on July 7th, 2017.

* Added feature to rotate oxAuth's public and private keys.
