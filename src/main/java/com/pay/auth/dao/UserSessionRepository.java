package com.pay.auth.dao;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.entity.UserSession;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Bulk revocations use flushAutomatically but NOT clearAutomatically: clearing the
 * persistence context mid-transaction would silently detach entities the caller has
 * already modified (e.g. a user whose status just changed).
 */
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    /**
     * Row lock prevents two concurrent refreshes with the same token both succeeding.
     * Kept free of fetch joins: PostgreSQL rejects FOR UPDATE on the nullable side of outer joins.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from UserSession s where s.refreshTokenHash = :hash")
    Optional<UserSession> findByRefreshTokenHashForUpdate(@Param("hash") String hash);

    boolean existsByAccessTokenJtiAndRevokedAtIsNull(String accessTokenJti);

    @Modifying(flushAutomatically = true)
    @Query("""
            update UserSession s set s.revokedAt = :now, s.revocationReason = :reason, s.updatedAt = :now
            where s.accessTokenJti = :jti and s.revokedAt is null
            """)
    int revokeByAccessTokenJti(@Param("jti") String jti, @Param("reason") RevocationReason reason, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            update UserSession s set s.revokedAt = :now, s.revocationReason = :reason, s.updatedAt = :now
            where s.user.id = :userId and s.revokedAt is null
            """)
    int revokeAllActiveForUser(@Param("userId") UUID userId, @Param("reason") RevocationReason reason, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            update UserSession s set s.revokedAt = :now, s.revocationReason = :reason, s.updatedAt = :now
            where s.familyId = :familyId and s.revokedAt is null
            """)
    int revokeFamily(@Param("familyId") UUID familyId, @Param("reason") RevocationReason reason, @Param("now") Instant now);
}
