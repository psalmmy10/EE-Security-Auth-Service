package com.pay.auth.dto.res;

import com.pay.auth.dto.common.EncryptedEnvelope;

import java.time.Instant;
import java.util.Map;

/**
 * DEV TOOL ONLY.
 *
 * @param headers     add all four to the real request
 * @param body        send as the real request body ({@code null} when there is no payload)
 * @param sessionKey  keep it; needed to decrypt the response
 * @param responseAad keep it; needed to decrypt the response
 * @param validUntil  the real request must be sent before this (replay window)
 */
public record E2EEncryptToolResponse(
        Map<String, String> headers,
        EncryptedEnvelope body,
        String sessionKey,
        String responseAad,
        Instant validUntil) {

    @Override
    public String toString() {
        return "E2EEncryptToolResponse[sessionKey=****, validUntil=" + validUntil + "]";
    }
}