var https = require('https')
var aws4  = require('aws4')

// to illustrate usage, we'll create a utility function to request and pipe to stdout
function request(opts) { https.request(opts, function(res) { res.pipe(process.stdout) }).end(opts.body || '') }

// aws4 will sign an options object as you'd pass to http.request, with an AWS service and region
var opts = {
    host: 's3.server.com',
    path: '/bucketname/?delete&x-purpose=SnapshotMetadata',
    method: 'POST',
    body: '<Delete><Quiet>true</Quiet><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/data-_sDkZteNQU6BvaNciUCyaQ.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/master.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/</Key></Object></Delete>',
    service: 's3',
    region: 'us-west-1',
    headers: {
        'Content-Type': 'application/xml',
        'Content-Md5': 'f9X58PeOGSK1Rdb/YHpLaw=='
    } 
}
// headers: Content-Length will be added automatically, X-Amz-Date will be taken from current DateTime

// aws4.sign() will sign and modify these options, ready to pass to http.request
aws4.sign(opts, { accessKeyId: 'your_access_key_here', secretAccessKey: 'your_secret_key_here' })

console.log(opts)
// The following properties of requestOptions are used in the signing or populated if they don't already exist:
//     hostname or host (will try to be determined from service and region if not given)
//     method (will use 'GET' if not given or 'POST' if there is a body)
//     path (will use '/' if not given)
//     body (will use '' if not given)
//     service (will try to be calculated from hostname or host if not given)
//     region (will try to be calculated from hostname or host or use 'us-east-1' if not given)
//     signQuery (to sign the query instead of adding an Authorization header, defaults to false)
//     extraHeadersToIgnore (an object with lowercase header keys to ignore when signing, eg { 'content-length': true })
//     extraHeadersToInclude (an object with lowercase header keys to include when signing, overriding any ignores)
//     headers['Host'] (will use hostname or host or be calculated if not given)
//     headers['Content-Type'] (will use 'application/x-www-form-urlencoded; charset=utf-8' if not given and there is a body)
//     headers['Date'] (used to calculate the signature date if given, otherwise new Date is used)

