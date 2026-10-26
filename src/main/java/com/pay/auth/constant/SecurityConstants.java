package com.pay.auth.constant;

public final class SecurityConstants {

    public static final String CLAIM_AUTHORITIES = "authorities";
    public static final String ROLE_PREFIX = "ROLE_";
    public static final String TOKEN_TYPE_BEARER = "Bearer";

    public static final String HEADER_E2E_KEY = "X-E2E-Key";
    public static final String HEADER_E2E_KEY_ID = "X-E2E-Key-Id";
    public static final String HEADER_E2E_TIMESTAMP = "X-E2E-Timestamp";
    public static final String HEADER_E2E_NONCE = "X-E2E-Nonce";
    public static final String HEADER_E2E_ENCRYPTED = "X-E2E-Encrypted";
    public static final String HEADER_CORRELATION_ID = "X-Correlation-Id";

    public static final String MDC_CORRELATION_ID = "correlationId";

    private static final String[] PUBLIC_ENDPOINTS = {
            ApiPaths.AUTH + "/signup",
            ApiPaths.AUTH + "/login",
            ApiPaths.AUTH + "/refresh",
            ApiPaths.CRYPTO + "/public-key",
            ApiPaths.JWKS,
            ApiPaths.DEV_E2E + "/**",   // controller exists only in dev; 404 elsewhere
            "/actuator/health",
            "/actuator/prometheus"   // staging/prod serve actuator on the internal management port only
    };

    private SecurityConstants() {
    }

    /** Defensive copy so no caller can mutate the allow-list at runtime. */
    public static String[] publicEndpoints() {
        return PUBLIC_ENDPOINTS.clone();
    }
}
