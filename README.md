# [s3proxy](s3proxy) - proxy with encryption

Modified https://github.com/abustany/s3proxy
### See [changes](s3proxy/README.md)

INFO: Multipart uploads are not supported. It's difficult to encrypt separate parts, instead of whole unencrypted file, and decrypt file back in original consistent state. Looks like it's a big challenge for now. Maybe later there will be a solution for this problem.

### How to [build and run](s3proxy/src/README.md) s3proxy

# [signature_v4](signature_v4) - examples of code for AWS signature V4

#### Additional information:

https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

https://github.com/mhart/aws4/tree/master?tab=readme-ov-file

