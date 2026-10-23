package com.pay.auth.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

import com.pay.auth.constant.enums.AuditEventType;

/**
 * Append-only security audit trail. userId is a plain column, not a foreign key:
 * audit evidence must outlive the account it describes. Principals are stored masked.
 */
@Getter
@Entity
@Table(name = "audit_logs")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditLog extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, updatable = false, length = 40)
    private AuditEventType eventType;

    @Column(name = "user_id", updatable = false)
    private UUID userId;

    @Column(name = "principal", updatable = false, length = 150)
    private String principal;

    @Column(name = "ip_address", updatable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", updatable = false, length = 255)
    private String userAgent;

    @Column(name = "detail", updatable = false, length = 500)
    private String detail;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    public static AuditLog of(AuditEventType eventType, UUID userId, String principal, String ipAddress,
                              String userAgent, String detail, Instant occurredAt) {
        AuditLog log = new AuditLog();
        log.eventType = eventType;
        log.userId = userId;
        log.principal = principal;
        log.ipAddress = ipAddress;
        log.userAgent = userAgent;
        log.detail = detail;
        log.occurredAt = occurredAt;
        return log;
    }
}
