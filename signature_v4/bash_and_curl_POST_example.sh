#!/bin/bash

# Example of elasticsearch DeleteMultipleObjects invocation, i.e.:
# POST https://s3.server.com/bucketname/?delete=&x-purpose=SnapshotMetadata
#
# with  http body:
# <Delete><Quiet>true</Quiet><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/data-_sDkZteNQU6BvaNciUCyaQ.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/master.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/</Key></Object></Delete>
#
# and (mandatory) headers:
#      Content-Type: application/xml
#      Host: s3.server.com
#      Content-Md5: <md5 hash hex of payload>   <- mandatory by Minio server, not by Amazon specifications
#      Content-Length: <length of payload>      <- mandatory by Minio server, not by Amazon specifications
#
# all headers must be sorted an lowercased in canonical_request and authorization_header by Amazon specifications
clear

ACCESS_KEY="your_access_key_here"
SECRET_KEY="your_secret_key_here"
http_path="/bucketname/"
http_query="?delete=&x-purpose=SnapshotMetadata"
host="s3.server.com"
region="us-west-1"
amazonDate="$(date -u +'%Y%m%dT%H%M%SZ')"
dateStamp="$(date -u +'%Y%m%d')"
method="POST"
service="s3"
content_type="application/xml"
payload="<Delete><Quiet>true</Quiet><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/data-_sDkZteNQU6BvaNciUCyaQ.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/master.dat</Key></Object><Object><Key>tests-V46bPKioR7uVceOXYh3NDw/</Key></Object></Delete>"
content_length="${#payload}"
content_md5=$(echo -ne "${payload}" | openssl dgst -md5 -binary | openssl enc -base64)

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

canonical_request="${method}\n${http_path}\n${http_query:1}\ncontent-length:${content_length}\ncontent-md5:${content_md5}\ncontent-type:${content_type}\nhost:${host}\nx-amz-content-sha256:${payload_hash}\nx-amz-date:${amazonDate}\n\ncontent-length;content-md5;content-type;host;x-amz-content-sha256;x-amz-date\n${payload_hash}"

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
authorization_header="Authorization: AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${dateStamp}/${region}/${service}/aws4_request, SignedHeaders=content-length;content-md5;content-type;host;x-amz-content-sha256;x-amz-date, Signature=${signature}"


# DEBUG
date -u
echo "amazonDate=${amazonDate}"
echo "dateStamp=${dateStamp}"

echo "payload=${payload}"
echo "payload_hash (x-amz-content-sha256)=${payload_hash}"
echo "SHA256 of empty string is always=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

echo "signingKey=${signingKey}"
echo "------------------------"

echo "canonical_request="
echo -en "${canonical_request}"
echo -en "\n------------------------\n"

echo "canonical_request sha256 hash="
echo -en "${canonical_request_hash}"
echo -en "\n------------------------\n"

echo "string_to_sign="
echo -en "${string_to_sign}"
echo -en "\n------------------------\n"

echo "signature=${signature}"
echo "------------------------"

echo "Authorization header=${authorization_header}"
echo "------------------------"

echo "now run the following curl:"
echo -e "curl -X ${method} https://${host}${http_path}${http_query} \
\n     -H \"x-amz-date: ${amazonDate}\" \
\n     -H \"Content-Type: ${content_type}\" \
\n     -H \"Content-Md5: ${content_md5}\" \
\n     -H \"Host: ${host}\" \
\n     -H \"Content-Length: ${content_length}\" \
\n     -H \"x-amz-content-sha256: ${payload_hash}\" \
\n     -H \"${authorization_header}\" \
\n     -d \"${payload}\""


curl -X ${method} https://${host}${http_path}${http_query} \
     -H "x-amz-date: ${amazonDate}" \
     -H "Content-Type: ${content_type}" \
     -H "Content-Md5: ${content_md5}" \
     -H "Content-Length: ${content_length}" \
     -H "Host: ${host}" \
     -H "x-amz-content-sha256: ${payload_hash}" \
     -H "${authorization_header}" \
     -d "${payload}"
