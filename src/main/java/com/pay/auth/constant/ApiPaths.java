package com.pay.auth.constant;

public final class ApiPaths {

    public static final String API_V1 = "/api/v1";
    public static final String AUTH = API_V1 + "/auth";
    public static final String USERS = API_V1 + "/users";
    public static final String ADMIN = API_V1 + "/admin";
    public static final String ADMIN_USERS = ADMIN + "/users";
    public static final String CRYPTO = API_V1 + "/crypto";
    public static final String JWKS = "/oauth2/jwks";
        /** Dev-profile-only E2E test helpers. */
    public static final String DEV_E2E = "/dev/e2e";

    private ApiPaths() {
    }
}
