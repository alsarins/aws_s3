# s3proxy - http proxy with transparent encryption (for PUT/POST requests) and decryption (for GET/HEAD).

- Modified version of https://github.com/abustany/s3proxy
- Created for elasticsearch backups with client side encryption in mind
- No authentication implemented (yet)
- Tested with local s3 compatible storages (Minio/Ceph), not tested with Amazon S3 (I do not have an account for testing)
- chunked encoding should be disabled (unsupported)
- Multipart uploads should be disabled (unsupported)
###  there are some workarounds for multipart problem, i.e:
  - Elasticsearch: tune "chunk_size" + "buffer_size" for s3 repository (for example 300MB both), to make it send exactly one file in exactly one PUT request, without multiparts
  - s3cmd tool: enable_multipart = False 

## Changes:
- added AWS Signature V4 (signature v2 is unsupported)
- added CONNECT method handling
- fixed Etag (md5) handling when encryption enabled
- fixed POST requests handling (for /?delete queries, not multipart starting/finishing requests)
- added configurable AwsDomain (for work with local s3 compatible storages), region and protocol for s3 server
- added trace level messages
- added pprof server on localhost:6060 for metrics monitoring
- performance optimizations
- added Dockerfile (not really tested docker container, but building process is successfull)

## TODO:
- fix multipart upload (large files) - hard to implement, tend to not support this feature
- fix some potential issues
- add support for legacy AWS Signature V2
- test with Amazon S3
- add support for chunked encoding HTTP requests

### usage examples:
```
s3proxy ~/.s3proxy.cfg
s3proxy -debug=true ~/.s3proxy.cfg
s3proxy -debug=trace ~/.s3proxy.cfg
```
