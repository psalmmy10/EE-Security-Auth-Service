package com.pay.auth.model;

/** Request origin metadata captured for sessions and the audit trail. */
public record ClientContext(String ipAddress, String userAgent) {
}
