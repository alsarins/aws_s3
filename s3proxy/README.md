# s3proxy - http proxy with transparent encryption (for PUT/POST requests) and decryption (for GET/HEAD).

## What is it:
- Modified version of https://github.com/abustany/s3proxy
- Created for elasticsearch backups with client side encryption in mind
- No authentication implemented (yet)
- Tested with local s3 compatible storages (Minio/Ceph), not tested with Amazon S3 (I do not have an account for testing)
- chunked encoding should be disabled (unsupported)
- Multipart uploads should be disabled (unsupported)
###  there are some workarounds for multipart problem, i.e:
  - Elasticsearch: tune "chunk_size" + "buffer_size" for s3 repository (for example 300MB both), to make it send exactly one file in exactly one PUT request, without multiparts
  - s3cmd tool: enable_multipart = False 

## How to [build and run](src/README.md) it

## Notice
You should take into account the following considerations:
- by using proxy your upload speed may be 2-3 times slower than in case of direct s3 access. This is due to the fact, that proxy needs to read whole HTTP request, encrypt it (if enabled), create new HTTP request with encrypted body, sign new encrypted body with AWS signature V4, send new signed HTTP request to s3 server. All of this steps takes times, and time depend on size of HTTP rquest body and CPU resources. There are no big chances to parallelize steps or pipe HTTP requests to s3 server in one client session, due to nature of HTTP protocol behavior with encryption enabled. If you do not need encryption, your better to not use s3proxy and use direct connection to s3 server.
- by using proxy to encrypt data, your should take into account, that memory and CPU requirements depend on HTTP request body size heavily. This is due to fact, that proxy needs to remain original HTTP body in memory and constructs internal copies of HTTP body (encrypted and signed with AWS signature for example) and hashing objects. In practice, if original HTTP request body is 150Mb, encrypting proxy may allocate up to 1Gb of additional memory for encrypting/decrypting/hashing/signing. Typical overhead is x3-x5 of original HTTP size.

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
