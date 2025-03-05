# s3proxy - http proxy with transparent encryption (for PUT/POST requests) and decryption (for GET/HEAD).

- Modified version of https://github.com/abustany/s3proxy
- Created for elasticsearch backups with client side encryption in mind
- No authentication implemented (yet)
- Tested with local s3 compatible storages (Minio/Ceph), not tested with Amazon S3 (I do not have an account for testing)
- chunked encoding should be disabled (unsupported)

## Changes:
- added AWS Signature V4 (signature v2 is unsupported)
- added CONNECT method handling
- fixed Etag (md5) handling when encryption enabled
- fixed POST requests handling
- added configurable AwsDomain (for work with local s3 compatible storages)

## TODO:
- fix multipart upload (large files)
- fix some potential issues
- make some parameters configurable in config file, i.e. region for bucket, http/https scheme for s3 server
- add Dockerfile for containerization
- add support for legacy AWS Signature V2
- test with Amazon S3
- add support for chunked encoding

### usage example:
s3proxy -debug=true ~/.s3proxy.cfg
