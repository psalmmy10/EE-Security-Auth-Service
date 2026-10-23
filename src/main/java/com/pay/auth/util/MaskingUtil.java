package com.pay.auth.util;

/** Masks PII before it reaches logs or the audit table. */
public final class MaskingUtil {

    private static final String MASK = "****";

    private MaskingUtil() {
    }

    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return email;
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return MASK;
        }
        String visible = email.substring(0, Math.min(2, at));
        return visible + MASK + email.substring(at);
    }
}
