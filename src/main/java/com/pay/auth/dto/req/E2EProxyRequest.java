package com.pay.auth.dto.req;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * DEV TOOL ONLY. A plain request that the server encrypts and sends to the real endpoint.
 *
 * @param payload     plain JSON body; omit for GET / no-body calls
 * @param accessToken optional access token (eyJ…) for protected endpoints
 */
public record E2EProxyRequest(
        @NotBlank @Pattern(regexp = "GET|POST|PUT|PATCH|DELETE", message = "method must be GET, POST, PUT, PATCH or DELETE")
        String method,
        @NotBlank @Pattern(regexp = "^/api/.*", message = "path must start with /api/")
        String path,
        JsonNode payload,
        String accessToken) {

    @Override
    public String toString() {
        return "E2EProxyRequest[method=" + method + ", path=" + path + ", accessToken=****]";
    }
}