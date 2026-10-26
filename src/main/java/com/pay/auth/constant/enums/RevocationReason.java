package com.pay.auth.constant.enums;

public enum RevocationReason {
    LOGOUT,
    LOGOUT_ALL,
    ROTATED,
    REUSE_DETECTED,
    ACCOUNT_INACTIVE,
    ROLE_CHANGED,
    /** Oldest session closed because the user exceeded the active-session limit. */
    SESSION_LIMIT,
    /** Login reached its absolute lifetime; refresh no longer extends it. */
    SESSION_EXPIRED
}
