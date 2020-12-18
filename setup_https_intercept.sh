#!/bin/bash

# Save original dir
pushd . >/dev/null
# Go to script location
cd "${0%/*}"

mkdir certs
cd certs
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Custom WS-HTTP proxy"
openssl genrsa -out cert.key 2048
mkdir specific_certs

# Back to orginal dir
popd
