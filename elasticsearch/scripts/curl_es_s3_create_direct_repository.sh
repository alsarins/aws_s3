#!/bin/bash
# elasticsearch command to create s3 repository "s3_direct" (without proxy)
curl -k -X PUT "https://elastic:passwd_here@localhost:9200/_snapshot/s3_direct?pretty" -H 'Content-Type: application/json' -d'
 {
   "type": "s3",
   "settings": {
     "bucket": "es-unencrypted-bucket",
     "endpoint": "s3.myserver.com",
     "protocol": "https",
     "client": "default",
     "path_style_access": "true",
     "disable_chunked_encoding": "true",
     "max_retries": 0
   }
 }'
