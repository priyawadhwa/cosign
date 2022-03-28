#!/bin/bash

# Create and verify the signature
openssl dgst -sha256 -sign test_blob_private_key -out test_blob_signature ./blob 
openssl dgst -sha256 -verify test_blob_public_key -signature test_blob_signature ./blob

echo "sha256 hash:"
sha256sum ./blob

echo "signature"
cat test_blob_signature | base64

echo "cert"
cat test_blob_cert.pem | base64

curl -X POST https://rekor.sigstore.dev/api/v1/log/entries -H 'Content-Type: application/json'  -d @http-body.json
