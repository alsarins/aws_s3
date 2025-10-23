#!/bin/bash
# elasticsearch command to create s3 repository "s3_proxy" (via encrypting http proxy on localhost:18000)
curl -u elastic -k -X PUT 'https://localhost:9200/_snapshot/s3_proxy?pretty' -H 'Content-Type: application/json' -d '{
   "type": "s3",
   "settings": {
     "bucket": "esbucket",
     "endpoint": "s3.myserver.com",
     "protocol": "http",
     "client": "default",
     "path_style_access": "true",
     "proxy.host": "127.0.0.1",
     "proxy.port": "18000",
     "disable_chunked_encoding": "true",
     "max_retries": 0,
     "chunk_size": "20Mb",
     "buffer_size": "20Mb"
   }
 }'
