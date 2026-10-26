package com.pay.auth.dto.res;


import com.pay.auth.dto.common.EncryptedEnvelope;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Map;

/**
 * DEV TOOL ONLY. Shows both sides of the wire so you can see the encryption happened.
 *
 * @param status             HTTP status returned by the real endpoint
 * @param responseEncrypted  whether the real endpoint's reply carried X-E2E-Encrypted: true
 * @param sentHeaders        the E2E headers actually sent
 * @param sentBody           the encrypted body actually sent (null for no-body calls)
 * @param receivedBody       the raw reply as it travelled (ciphertext when encrypted)
 * @param decryptedResponse  the reply in plain JSON
 */
public record E2EProxyResponse(
        int status,
        boolean responseEncrypted,
        Map<String, String> sentHeaders,
        EncryptedEnvelope sentBody,
        JsonNode receivedBody,
        JsonNode decryptedResponse) {
}
