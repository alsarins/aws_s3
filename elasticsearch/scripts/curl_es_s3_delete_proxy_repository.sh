#!/bin/bash
# elasticsearch command to delete "s3_proxy" repository
curl -k -X DELETE "https://elastic:vpd38ATJ@localhost:9200/_snapshot/s3_proxy?pretty"
