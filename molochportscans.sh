#!/bin/bash

DATE=$(date +'%y%m%d')

curl -XGET "http://localhost:9200/sessions-$DATE/_search" \
-d '{"size":0,"query":{"bool":{"must":[{"match":{"tcpflags.fin":0}},{"range":{"tcpflags.syn":{"gte":"1"}}},{"range":{"firstPacket":{"gte":"now-300s"}}}]}},"aggs":{"ipSrc":{"terms":{"field":"ipSrc"},"aggs":{"ipDst":{"terms":{"field":"ipDst","order":{"unique_port_count":"desc"}},"aggs":{"unique_port_count":{"cardinality":{"field":"p2"}}}}}}}}' | \
jq -r  '.aggregations.ipSrc.buckets[] | "\"ip.src == \(.key) && ip.dst == \(.ipDst.buckets[] | .key)\" \tunique port count: \(.ipDst.buckets[] | .unique_port_count.value )"' | \
awk '$11 > 5 {print $0}' | \
sort -u