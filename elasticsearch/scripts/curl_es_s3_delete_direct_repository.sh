#!/bin/bash
# elasticsearch command to delete "s3_direct" repository
curl -u elastic -k -X DELETE "https://localhost:9200/_snapshot/s3_direct?pretty"
