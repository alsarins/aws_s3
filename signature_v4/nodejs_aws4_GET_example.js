// From examples of https://github.com/mhart/aws4/tree/master?tab=readme-ov-file
// Requires node.js version >= v14
//
// This is the algorithm POSTMAN uses inside to generate signature: 
// https://community.postman.com/t/get-aws-canonical-request/14185
// https://github.com/postmanlabs/postman-runtime/blob/c18367f75b6aeed8950daee5183e5db76477caa7/lib/authorizer/aws4.js#L223
// 
// 1) install node.js v20:
// cd ~
// curl -sL https://deb.nodesource.com/setup_20.x -o nodesource_setup.sh
// sudo bash nodesource_setup.sh
//
// 2) install module:
// npm install aws4
// 
// 3) run script:
// node nodejs_aws4.js
//
var https = require('https')
var aws4  = require('aws4')

// to illustrate usage, we'll create a utility function to request and pipe to stdout
function request(opts) { https.request(opts, function(res) { res.pipe(process.stdout) }).end(opts.body || '') }

// aws4 will sign an options object as you'd pass to http.request, with an AWS service and region
var opts = { host: 'my-precious-bucket.s3.amazonaws.com', path: '/', method: 'GET', body: '', service: 's3', region: 'us-east-1', signQuery: false, headers: { 'Date': 'September 15, 2015 12:45:00' } }

// aws4.sign() will sign and modify these options, ready to pass to http.request
aws4.sign(opts, { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' })

console.log(opts)

/* output should be the following:
{
  host: 'my-precious-bucket.s3.amazonaws.com',
  path: '/',
  method: 'GET',
  body: '',
  service: 's3',
  region: 'us-east-1',
  signQuery: false,
  headers: {
    Date: 'September 15, 2015 12:45:00',
    Host: 'my-precious-bucket.s3.amazonaws.com',
    'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'X-Amz-Date': '20150915T124500Z',
    Authorization: 'AWS4-HMAC-SHA256 Credential=undefined/20150915/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=e096e0f48090857a26df4d472e36dac35b2cc066d10f75980751b7b876c6d52a'
  }
}
*/
