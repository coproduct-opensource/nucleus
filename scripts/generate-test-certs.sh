#!/bin/bash
# Generate test certificates for mTLS testing
#
# This script creates a self-signed CA and certificates for:
# - nucleus-node (server)
# - workstream-kg (client)
# - github CI/CD (client)
#
# SPIFFE IDs are embedded in the Subject Alternative Name (SAN).
#
# Notes for rustls/tonic compatibility:
# - CA certificates use a config file to avoid duplicate extensions
# - Private keys are converted to PKCS#8 format (rustls requirement)
# - The generated env.sh uses the PKCS#8 key files

set -euo pipefail

CERT_DIR="${1:-/tmp/nucleus-mtls-test}"
TRUST_DOMAIN="${2:-nucleus.local}"

echo "=== Generating test certificates for mTLS ==="
echo "Output directory: $CERT_DIR"
echo "Trust domain: $TRUST_DOMAIN"
echo

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA key and certificate
# Note: We use a config file to avoid duplicate extensions that rustls rejects
echo "1. Generating CA..."
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem

cat > ca.cnf << 'CAEOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = nucleus-test-ca

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
CAEOF

openssl req -new -x509 -key ca-key.pem -out ca.pem -days 365 -config ca.cnf
rm ca.cnf

# Generate server certificate (for nucleus-node)
echo "2. Generating server certificate..."
SERVER_SPIFFE_ID="spiffe://$TRUST_DOMAIN/ns/servers/sa/nucleus-node"

openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -key server-key.pem -out server.csr \
    -subj "/CN=nucleus-node" \
    -addext "subjectAltName=URI:$SERVER_SPIFFE_ID,DNS:localhost,DNS:nucleus.local,IP:127.0.0.1"

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out server.pem -days 30 \
    -extfile <(printf "subjectAltName=URI:$SERVER_SPIFFE_ID,DNS:localhost,DNS:nucleus.local,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

rm server.csr

# Convert server key to PKCS#8 (required by rustls/tonic)
openssl pkcs8 -topk8 -nocrypt -in server-key.pem -out server-key-pkcs8.pem

# Generate client certificate (for workstream-kg)
echo "3. Generating client certificate..."
CLIENT_SPIFFE_ID="spiffe://$TRUST_DOMAIN/ns/workstream-kg/sa/orchestrator"

openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -key client-key.pem -out client.csr \
    -subj "/CN=workstream-kg" \
    -addext "subjectAltName=URI:$CLIENT_SPIFFE_ID"

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out client.pem -days 30 \
    -extfile <(printf "subjectAltName=URI:$CLIENT_SPIFFE_ID\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth")

rm client.csr

# Convert client key to PKCS#8 (required by rustls/tonic)
openssl pkcs8 -topk8 -nocrypt -in client-key.pem -out client-key-pkcs8.pem

# Generate a second client (GitHub CI/CD identity)
echo "4. Generating CI/CD client certificate..."
CICD_SPIFFE_ID="spiffe://$TRUST_DOMAIN/ns/github/sa/myorg/myrepo"

openssl ecparam -name prime256v1 -genkey -noout -out cicd-key.pem
openssl req -new -key cicd-key.pem -out cicd.csr \
    -subj "/CN=github-cicd" \
    -addext "subjectAltName=URI:$CICD_SPIFFE_ID"

openssl x509 -req -in cicd.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out cicd.pem -days 30 \
    -extfile <(printf "subjectAltName=URI:$CICD_SPIFFE_ID\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth")

rm cicd.csr

# Convert CI/CD key to PKCS#8 (required by rustls/tonic)
openssl pkcs8 -topk8 -nocrypt -in cicd-key.pem -out cicd-key-pkcs8.pem

# Verify certificates
echo
echo "=== Verifying certificates ==="
echo "CA:"
openssl x509 -in ca.pem -noout -subject -issuer

echo
echo "Server (nucleus-node):"
openssl x509 -in server.pem -noout -subject -ext subjectAltName

echo
echo "Client (workstream-kg):"
openssl x509 -in client.pem -noout -subject -ext subjectAltName

echo
echo "CI/CD (github):"
openssl x509 -in cicd.pem -noout -subject -ext subjectAltName

# Create environment file
cat > env.sh << EOF
# Environment variables for nucleus-node mTLS
export NUCLEUS_NODE_GRPC_TLS_CERT="$CERT_DIR/server.pem"
export NUCLEUS_NODE_GRPC_TLS_KEY="$CERT_DIR/server-key-pkcs8.pem"
export NUCLEUS_NODE_GRPC_TLS_CA="$CERT_DIR/ca.pem"

# Environment variables for workstream-kg client
export NUCLEUS_CLIENT_CERT="$CERT_DIR/client.pem"
export NUCLEUS_CLIENT_KEY="$CERT_DIR/client-key-pkcs8.pem"
export NUCLEUS_CA_CERT="$CERT_DIR/ca.pem"
export NUCLEUS_SERVER_NAME="localhost"
export NUCLEUS_GRPC_URL="https://127.0.0.1:4443"
EOF

echo
echo "=== Certificate generation complete ==="
echo
echo "Files created in $CERT_DIR:"
ls -la "$CERT_DIR"
echo
echo "To use these certificates, source the environment file:"
echo "  source $CERT_DIR/env.sh"
echo
echo "Then start nucleus-node with:"
echo "  nucleus-node --grpc-listen 127.0.0.1:4080 \\"
echo "              --grpc-tls-cert \$NUCLEUS_NODE_GRPC_TLS_CERT \\"
echo "              --grpc-tls-key \$NUCLEUS_NODE_GRPC_TLS_KEY \\"
echo "              --grpc-tls-ca \$NUCLEUS_NODE_GRPC_TLS_CA"
