package com.pay.auth.dto.req;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * DEV TOOL ONLY. What you want to send: the HTTP method, the API path, and the plain JSON body
 * (omit {@code payload} for calls without a body, such as GET /me).
 */
public record E2EEncryptToolRequest(
        @NotBlank @Pattern(regexp = "GET|POST|PUT|PATCH|DELETE", message = "method must be GET, POST, PUT, PATCH or DELETE")
        String method,
        @NotBlank @Pattern(regexp = "^/api/.*", message = "path must start with /api/")
        String path,
        JsonNode payload) {
}