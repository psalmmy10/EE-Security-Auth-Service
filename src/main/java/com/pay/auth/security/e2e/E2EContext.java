package com.pay.auth.security.e2e;

import javax.crypto.SecretKey;

/**
 * Per-request crypto context, held as a request attribute (never in a static/thread-local).
 *
 * @param key         client-generated AES-256 key, unwrapped with our RSA private key
 * @param requestAad  METHOD|PATH|TIMESTAMP|NONCE — binds the request ciphertext to this call
 * @param responseAad RESP|METHOD|PATH|NONCE — binds the response to the request that caused it
 */
public record E2EContext(SecretKey key, byte[] requestAad, byte[] responseAad) {

    public static final String REQUEST_ATTRIBUTE = E2EContext.class.getName();

    @Override
    public String toString() {
        return "E2EContext[key=****]";
    }
}
