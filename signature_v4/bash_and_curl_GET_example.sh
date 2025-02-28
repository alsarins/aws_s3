#!/bin/bash

# https://czak.pl/2015/09/15/s3-rest-api-with-curl
clear

# reference valiables, from the example above
ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
http_path="/"
host="my-precious-bucket.s3.amazonaws.com"
region="us-east-1"
amazonDate="20150915T124500Z"
dateStamp="20150915"
method="GET"
http_query=""
service="s3"
# real values should be like:
# amazonDate="$(date -u +'%Y%m%dT%H%M%SZ')"
# dateStamp="$(date -u +'%Y%m%d')"
#
# no payload for GET requests assumed
payload=""

function sha256 {
    echo -ne "$1" | openssl dgst -sha256 -hex | awk '{print $2}'
}

function hmac_sha256 {
  key="$1"
  data="$2"
  echo -en "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
}

# get payload sha256 hash
payload_hash=$(sha256 "${payload}")

# canonical request: описание формата
# Допустим у нас вызван POST https://s3.example.com/bucketname/?delete&x-purpose=SnapshotMetadata
#
# <HTTPMethod>\n        HTTP метод. Из примера: 'POST\n'
# <CanonicalURI>\n      то, что после имени домена до ? или до окончания URL. Из примера: '/bucketname/\n'
# <CanonicalQueryString>\n  то, что после ? в URL, в сортированном порядке. Из примера: 'delete&x-purpose=SnapshotMetadata\n'
# <CanonicalHeaders>\n  список заголовков в виде имя:значение\n. Обязательные заголовки: host,x-amz-content-sha256,x-amz-date.Могут быть и необязательные, например: Content-Type,Content-Md5,все остальные x-amz* которые планируется передавать. Список заголовков обязательно должен передаваться в алфавитном порядке
# <SignedHeaders>\n     список заголовков через запятую тот же что и в CanonicalHeaders в алфавитном порядке
# <HashedPayload>       sha256 хэш передаваемого payload. То есть то что в payload_hash переменной. В конце не добавляется \n
#
# CanonicalHeaders:
# You must include the host header (HTTP/1.1) or the :authority header (HTTP/2), and any x-amz-* headers in the signature. You can optionally include other standard headers in the signature, such as content-type.

canonical_request="${method}\n${http_path}\n${http_query}\nhost:${host}\nx-amz-content-sha256:${payload_hash}\nx-amz-date:${amazonDate}\n\nhost;x-amz-content-sha256;x-amz-date\n${payload_hash}"

canonical_request_hash=$(sha256 "${canonical_request}")

# string_to_sign in signature v4
#
# формат строки для подписания:
# AWS4-HMAC-SHA256\n
# <Timestamp>\n   то, что содержится в ${amazonDate} (UTC time in ISO 8601). Пример: 20250227T201340Z\n
# <Scope>\n  Строка вида: ${dateStamp}/${region}/${service}/aws4_request. В нашем примере: 20250227/us-west-1/s3//aws4_request\n
# <CanonicalRequestHash>   sha256 хэш canonical_request. У нас ${canonical_request_hash}

string_to_sign="AWS4-HMAC-SHA256\n${amazonDate}\n${dateStamp}/${region}/${service}/aws4_request\n${canonical_request_hash}"

# signing key
# Four-step signing key calculation in signature v4
dateKey=$(hmac_sha256 key:"AWS4${SECRET_KEY}" ${dateStamp})
dateRegionKey=$(hmac_sha256 hexkey:${dateKey} ${region})
dateRegionServiceKey=$(hmac_sha256 hexkey:${dateRegionKey} ${service})
signingKey=$(hmac_sha256 hexkey:${dateRegionServiceKey} "aws4_request")

# get signature
signature=$(hmac_sha256 hexkey:${signingKey} "${string_to_sign}")

# set Authorization header
# имеет вид: Authorization: <Algorithm> Credential=<Access Key ID/Scope>, SignedHeaders=<SignedHeaders>, Signature=<Signature>
authorization_header="Authorization: AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${dateStamp}/${region}/${service}/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${signature}"


# DEBUG
date -u
echo "amazonDate=${amazonDate}"
echo "dateStamp=${dateStamp}"

echo "payload=${payload}"
echo "payload_hash (x-amz-content-sha256)=${payload_hash}"
echo "SHA256 of empty string is always=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

echo "canonical_request="
echo -en "${canonical_request}"
echo -en "\n------------------------\n"

echo "canonical_request sha256 hash="
echo -en "${canonical_request_hash}"
echo -en "\n------------------------\n"

echo "string_to_sign="
echo -en "${string_to_sign}"
echo -en "\n------------------------\n"

echo "signingKey=${signingKey}"
echo "------------------------"

echo "signature=${signature}"
echo "------------------------"

echo "Authorization header=${authorization_header}"
echo "------------------------"

echo "now run the following curl:"
echo -e "curl -x ${method} https://${host}${http_path} \
\n     -H \"${authorization_header}\" \
\n     -H \"x-amz-content-sha256: ${payload_hash}\" \
\n     -H \"x-amz-date: ${amazonDate}\""

curl -X ${method} https://${host}${http_path} \
     -H "${authorization_header}" \
     -H "x-amz-content-sha256: ${payload_hash}" \
     -H "x-amz-date: ${amazonDate}"

# reference curl from the example. With hashes and signatures
# curl -v https://my-precious-bucket.s3.amazonaws.com/
#      -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20150915/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=182072eb53d85c36b2d791a1fa46a12d23454ec1e921b02075c23aee40166d5a"
#      -H "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#      -H "x-amz-date: 20150915T124500Z"
