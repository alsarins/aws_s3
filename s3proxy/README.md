s3proxy - http proxy with transparent encryption (for PUT/POST requests) and decryption (for GET/HEAD).

- Modified https://github.com/abustany/s3proxy
- Created for elasticsearch client side encryption of snapshots in mind
- No authentication implemented (yet)
- Uses AWS Signature V4 (signature v2 is unsupported)
- Tested with local s3 compatible storages (Minio/Ceph), not tested with Amazon S3 (I do not have an account for testing)


TODO:
- fix some potential issues
- make some parameters configurable in config file, i.e. region for bucket
- add Dockerfile for containerization
- add support for legacy ASW Signature V2
- test with Amazon S3

### usage example:
s3proxy -debug=true ~/.s3proxy.cfg

