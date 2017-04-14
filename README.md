# molochsessions

crud, simple script to query moloch api via cli

###Examples
```sh
molochsessions.pl -v

molochsessions.pl -j -c 10 | jq '.data[]'

molochsessions.pl -e "protocols == udp && port == 19" -j -c 500 | jq '.data[] | "\(.ipSrc) \(.ipDst)"' | sort | uniq -c | sort -n
```