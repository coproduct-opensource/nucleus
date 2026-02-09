#!/usr/bin/env nu
# Generate test certificates for mTLS testing
#
# Creates a self-signed CA and certificates for:
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

def main [
    cert_dir: string = "/tmp/nucleus-mtls-test"   # Output directory for certificates
    trust_domain: string = "nucleus.local"         # SPIFFE trust domain
] {
    print "=== Generating test certificates for mTLS ==="
    print $"Output directory: ($cert_dir)"
    print $"Trust domain: ($trust_domain)"
    print ""

    mkdir $cert_dir

    # ── 1. Generate CA ──────────────────────────────────────────────
    print "1. Generating CA..."
    ^openssl ecparam -name prime256v1 -genkey -noout -out $"($cert_dir)/ca-key.pem"

    # Use a config file to avoid duplicate extensions that rustls rejects
    let ca_cnf = $"($cert_dir)/ca.cnf"
    "[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = nucleus-test-ca

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign" | save -f $ca_cnf

    ^openssl req -new -x509 -key $"($cert_dir)/ca-key.pem" -out $"($cert_dir)/ca.pem" -days 365 -config $ca_cnf
    rm $ca_cnf

    # ── 2. Generate server certificate (nucleus-node) ───────────────
    print "2. Generating server certificate..."
    let server_spiffe = $"spiffe://($trust_domain)/ns/servers/sa/nucleus-node"

    ^openssl ecparam -name prime256v1 -genkey -noout -out $"($cert_dir)/server-key.pem"
    ^openssl req -new -key $"($cert_dir)/server-key.pem" -out $"($cert_dir)/server.csr" -subj "/CN=nucleus-node" -addext $"subjectAltName=URI:($server_spiffe),DNS:localhost,DNS:nucleus.local,IP:127.0.0.1"

    let ext_file = (^mktemp | str trim)
    $"subjectAltName=URI:($server_spiffe),DNS:localhost,DNS:nucleus.local,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" | save -f $ext_file
    ^openssl x509 -req -in $"($cert_dir)/server.csr" -CA $"($cert_dir)/ca.pem" -CAkey $"($cert_dir)/ca-key.pem" -CAcreateserial -out $"($cert_dir)/server.pem" -days 30 -extfile $ext_file
    rm $ext_file $"($cert_dir)/server.csr"

    # Convert to PKCS#8 (required by rustls/tonic)
    ^openssl pkcs8 -topk8 -nocrypt -in $"($cert_dir)/server-key.pem" -out $"($cert_dir)/server-key-pkcs8.pem"

    # ── 3. Generate client certificate (workstream-kg) ──────────────
    print "3. Generating client certificate..."
    let client_spiffe = $"spiffe://($trust_domain)/ns/workstream-kg/sa/orchestrator"

    ^openssl ecparam -name prime256v1 -genkey -noout -out $"($cert_dir)/client-key.pem"
    ^openssl req -new -key $"($cert_dir)/client-key.pem" -out $"($cert_dir)/client.csr" -subj "/CN=workstream-kg" -addext $"subjectAltName=URI:($client_spiffe)"

    let ext_file = (^mktemp | str trim)
    $"subjectAltName=URI:($client_spiffe)\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth" | save -f $ext_file
    ^openssl x509 -req -in $"($cert_dir)/client.csr" -CA $"($cert_dir)/ca.pem" -CAkey $"($cert_dir)/ca-key.pem" -CAcreateserial -out $"($cert_dir)/client.pem" -days 30 -extfile $ext_file
    rm $ext_file $"($cert_dir)/client.csr"

    # Convert to PKCS#8
    ^openssl pkcs8 -topk8 -nocrypt -in $"($cert_dir)/client-key.pem" -out $"($cert_dir)/client-key-pkcs8.pem"

    # ── 4. Generate CI/CD client certificate (GitHub) ───────────────
    print "4. Generating CI/CD client certificate..."
    let cicd_spiffe = $"spiffe://($trust_domain)/ns/github/sa/myorg/myrepo"

    ^openssl ecparam -name prime256v1 -genkey -noout -out $"($cert_dir)/cicd-key.pem"
    ^openssl req -new -key $"($cert_dir)/cicd-key.pem" -out $"($cert_dir)/cicd.csr" -subj "/CN=github-cicd" -addext $"subjectAltName=URI:($cicd_spiffe)"

    let ext_file = (^mktemp | str trim)
    $"subjectAltName=URI:($cicd_spiffe)\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth" | save -f $ext_file
    ^openssl x509 -req -in $"($cert_dir)/cicd.csr" -CA $"($cert_dir)/ca.pem" -CAkey $"($cert_dir)/ca-key.pem" -CAcreateserial -out $"($cert_dir)/cicd.pem" -days 30 -extfile $ext_file
    rm $ext_file $"($cert_dir)/cicd.csr"

    # Convert to PKCS#8
    ^openssl pkcs8 -topk8 -nocrypt -in $"($cert_dir)/cicd-key.pem" -out $"($cert_dir)/cicd-key-pkcs8.pem"

    # ── Verify ──────────────────────────────────────────────────────
    print ""
    print "=== Verifying certificates ==="
    print "CA:"
    ^openssl x509 -in $"($cert_dir)/ca.pem" -noout -subject -issuer

    print ""
    print "Server (nucleus-node):"
    ^openssl x509 -in $"($cert_dir)/server.pem" -noout -subject -ext subjectAltName

    print ""
    print "Client (workstream-kg):"
    ^openssl x509 -in $"($cert_dir)/client.pem" -noout -subject -ext subjectAltName

    print ""
    print "CI/CD (github):"
    ^openssl x509 -in $"($cert_dir)/cicd.pem" -noout -subject -ext subjectAltName

    # ── Generate env.sh ─────────────────────────────────────────────
    $"# Environment variables for nucleus-node mTLS
export NUCLEUS_NODE_GRPC_TLS_CERT=\"($cert_dir)/server.pem\"
export NUCLEUS_NODE_GRPC_TLS_KEY=\"($cert_dir)/server-key-pkcs8.pem\"
export NUCLEUS_NODE_GRPC_TLS_CA=\"($cert_dir)/ca.pem\"

# Environment variables for workstream-kg client
export NUCLEUS_CLIENT_CERT=\"($cert_dir)/client.pem\"
export NUCLEUS_CLIENT_KEY=\"($cert_dir)/client-key-pkcs8.pem\"
export NUCLEUS_CA_CERT=\"($cert_dir)/ca.pem\"
export NUCLEUS_SERVER_NAME=\"localhost\"
export NUCLEUS_GRPC_URL=\"https://127.0.0.1:4443\"
" | save -f $"($cert_dir)/env.sh"

    print ""
    print "=== Certificate generation complete ==="
    print ""
    print $"Files created in ($cert_dir):"
    ls $cert_dir | select name size | print
    print ""
    print $"To use these certificates, source the environment file:"
    print $"  source ($cert_dir)/env.sh"
}
