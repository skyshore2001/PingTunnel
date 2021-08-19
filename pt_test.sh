#!/bin/sh

# simple test:
#	curl localhost:10081
# test to tranfer bigfile:
#	(create 200M bigfile on server folder /var/www/html: dd if=/dev/zero of=bigfile bs=1M count=200)
#	curl localhost:10081/bigfile -O

./ptunnel -p localhost -lp 10081 -da localhost -dp 80 $@
#./ptunnel -p yibo2.oliveche.com -lp 10081 -da localhost -dp 80 $@
