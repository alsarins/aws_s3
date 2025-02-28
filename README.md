# s3proxy

Modified https://github.com/abustany/s3proxy
- added CONNECT method handler
- added configurable AwsDomain
- fixed Etag replacement for encrypted objects: should work with PUT anf GET requests, tested with s3cmd tool
- TODO: need solution for aws signature error with POST requests with payload and encryption enabled
- TODO: need to implement signature v4 instead of signature v2 (legacy) as of now

# signature_v4

https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

- examples of code for AWS signature V4

