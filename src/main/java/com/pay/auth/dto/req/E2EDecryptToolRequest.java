package com.pay.auth.dto.req;

import com.pay.auth.dto.common.EncryptedEnvelope;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * DEV TOOL ONLY. The {@code sessionKey} and {@code responseAad} returned by /dev/e2e/encrypt,
 * plus the encrypted {iv, data} body the real endpoint sent back.
 */
public record E2EDecryptToolRequest(
        @NotBlank String sessionKey,
        @NotBlank String responseAad,
        @NotNull EncryptedEnvelope response) {

    @Override
    public String toString() {
        return "E2EDecryptToolRequest[sessionKey=****, responseAad=" + responseAad + "]";
    }
}