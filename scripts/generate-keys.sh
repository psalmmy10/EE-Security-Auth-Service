#!/usr/bin/env bash
# Generates the PKCS#12 keystore holding two SEPARATE RSA-3072 key pairs:
#   jwt-signing         -> signs access tokens (published via /oauth2/jwks)
#   payload-encryption  -> unwraps client AES keys for E2E payloads
# Store the output in your secret manager / mounted secret, never in git.
set -euo pipefail
KEYSTORE="${1:-auth-keys.p12}"
read -rsp "Keystore password: " PASS; echo

for ALIAS in jwt-signing payload-encryption; do
  keytool -genkeypair -alias "$ALIAS" -keyalg RSA -keysize 3072 -sigalg SHA256withRSA \
    -validity 365 -dname "CN=banffpay-auth-${ALIAS}" \
    -storetype PKCS12 -keystore "$KEYSTORE" -storepass "$PASS" -keypass "$PASS"
done
chmod 600 "$KEYSTORE"
echo "Created $KEYSTORE with aliases: jwt-signing, payload-encryption"
