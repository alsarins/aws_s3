#!/bin/bash
# create elasticsearch snapshot - use "s3_direct" (without proxy) repository
curl -u elastic -k -X PUT 'https://localhost:9200/_snapshot/s3_direct/%3Cmy_snapshot_%7Bnow%2Fd%7D%3E?pretty'
