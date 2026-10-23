package com.pay.auth.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.model.ClientContext;

/**
 * One row per issued token pair. Rows sharing a familyId form a refresh-token rotation
 * chain: presenting an already-rotated refresh token revokes the whole family
 * (OAuth 2.0 Security BCP, refresh token reuse detection).
 * Only the SHA-256 of the refresh token is stored; the raw value exists only client-side.
 */
@Getter
@Entity
@Table(name = "user_sessions")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserSession extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(name = "family_id", nullable = false, updatable = false)
    private UUID familyId;

    @Column(name = "access_token_jti", nullable = false, unique = true, updatable = false, length = 64)
    private String accessTokenJti;

    @Column(name = "refresh_token_hash", nullable = false, unique = true, updatable = false, length = 64)
    private String refreshTokenHash;

    @Column(name = "ip_address", length = 45, updatable = false)
    private String ipAddress;

    @Column(name = "user_agent", length = 255, updatable = false)
    private String userAgent;

    @Column(name = "access_expires_at", nullable = false, updatable = false)
    private Instant accessExpiresAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", length = 30)
    private RevocationReason revocationReason;

    public static UserSession open(User user, UUID familyId, String accessTokenJti, String refreshTokenHash,
                                   ClientContext client, Instant accessExpiresAt, Instant expiresAt) {
        UserSession session = new UserSession();
        session.user = user;
        session.familyId = familyId;
        session.accessTokenJti = accessTokenJti;
        session.refreshTokenHash = refreshTokenHash;
        session.ipAddress = client.ipAddress();
        session.userAgent = client.userAgent();
        session.accessExpiresAt = accessExpiresAt;
        session.expiresAt = expiresAt;
        return session;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public void revoke(RevocationReason reason, Instant now) {
        if (revokedAt == null) {
            this.revokedAt = now;
            this.revocationReason = reason;
        }
    }
}
