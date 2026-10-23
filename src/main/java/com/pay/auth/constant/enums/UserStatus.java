package com.pay.auth.constant.enums;

public enum UserStatus {
    ACTIVE,
    /** Locked by an administrator (distinct from the temporary brute-force lock). */
    LOCKED,
    DISABLED
}
