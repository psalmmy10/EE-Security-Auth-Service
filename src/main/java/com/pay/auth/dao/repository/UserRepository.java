package com.pay.auth.dao.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.pay.auth.dao.entity.User;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmail(String email);

    /** Single round-trip for login: user + roles + permissions (Sets, so no cartesian bag issue). */
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesByEmail(String email);

    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesById(UUID id);

    /** Atomic increment: safe under concurrent brute-force attempts without row locks. */
    @Modifying(flushAutomatically = true)
    @Query("update User u set u.failedLoginAttempts = u.failedLoginAttempts + 1, u.updatedAt = :now where u.id = :id")
    int incrementFailedAttempts(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            update User u set u.lockedUntil = :lockedUntil, u.failedLoginAttempts = 0, u.updatedAt = :now
            where u.id = :id and u.failedLoginAttempts >= :maxAttempts
            """)
    int lockIfThresholdReached(@Param("id") UUID id, @Param("maxAttempts") int maxAttempts,
                               @Param("lockedUntil") Instant lockedUntil, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            update User u set u.failedLoginAttempts = 0, u.lockedUntil = null, u.lastLoginAt = :now, u.updatedAt = :now
            where u.id = :id
            """)
    int markSuccessfulLogin(@Param("id") UUID id, @Param("now") Instant now);
}
