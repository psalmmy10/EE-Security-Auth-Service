package com.pay.auth.dto.res;

/**
 * @param keyId              send back in X-E2E-Key-Id so key rotation is detectable
 * @param keyAlgorithm       RSA-OAEP-256 (RSA-OAEP, SHA-256, MGF1-SHA-256)
 * @param contentEncryption  A256GCM
 * @param publicKey          base64 X.509 SubjectPublicKeyInfo (WebCrypto "spki")
 */
public record PublicKeyResponse(String keyId, String keyAlgorithm, String contentEncryption, String publicKey) {
}
