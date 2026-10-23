package com.pay.auth.dto.common;

import org.springframework.util.StringUtils;

/**
 * Wire format for encrypted request and response bodies.
 *
 * @param iv   base64 96-bit AES-GCM nonce, unique per message
 * @param data base64 ciphertext with the 128-bit GCM authentication tag appended
 */
public record EncryptedEnvelope(String iv, String data) {

    public boolean isComplete() {
        return StringUtils.hasText(iv) && StringUtils.hasText(data);
    }
}
