package com.pay.auth.event;

import java.time.Instant;
import java.util.UUID;

import com.pay.auth.constant.enums.AuditEventType;
import com.pay.auth.model.ClientContext;
import com.pay.auth.util.MaskingUtil;

/**
 * Observer pattern: services publish what happened; the audit listener decides how it is
 * recorded. Services stay decoupled from audit storage (SRP / DIP).
 */
public record AuthAuditEvent(
        AuditEventType type,
        UUID userId,
        String principal,
        String ipAddress,
        String userAgent,
        String detail,
        Instant occurredAt) {

    public static AuthAuditEvent of(AuditEventType type, UUID userId, String rawPrincipal,
                                    ClientContext client, String detail, Instant occurredAt) {
        return new AuthAuditEvent(
                type,
                userId,
                MaskingUtil.maskEmail(rawPrincipal),
                client == null ? null : client.ipAddress(),
                client == null ? null : client.userAgent(),
                detail,
                occurredAt);
    }
}
