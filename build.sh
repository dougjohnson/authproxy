#!/bin/bash 
set -e

docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp authproxy sh -c "go build -v"
mv myapp ansible/roles/authproxy/files/authproxy
echo "-- authproxy binary successfully created in ansible/roles/authproxy/files/"
