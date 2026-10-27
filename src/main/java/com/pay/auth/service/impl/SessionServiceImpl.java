package com.pay.auth.service.impl;

import com.pay.auth.config.properties.JwtProperties;
import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.dao.entity.User;
import com.pay.auth.dao.entity.UserSession;
import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dao.repository.UserSessionRepository;
import com.pay.auth.exception.InvalidTokenException;
import com.pay.auth.exception.TokenReuseDetectedException;
import com.pay.auth.model.AccessToken;
import com.pay.auth.model.AuthenticatedSession;
import com.pay.auth.model.ClientContext;
import com.pay.auth.model.IssuedTokens;
import com.pay.auth.service.SessionService;
import com.pay.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SessionServiceImpl implements SessionService {

    private final UserSessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    @Override
    @Transactional
    public IssuedTokens openSession(User user, ClientContext client) {
        Instant now = clock.instant();
        enforceSessionLimit(user.getId(), now);
        IssuedTokens tokens = issueInFamily(user, UUID.randomUUID(), now.plus(jwtProperties.sessionAbsoluteTtl()), client);
        log.info("Session opened (userId={}, accessExpiresAt={}, refreshExpiresAt={})",
                user.getId(), tokens.accessTokenExpiresAt(), tokens.refreshTokenExpiresAt());
        return tokens;
    }

    /**
     * Refresh-token rotation with reuse detection. noRollbackFor ensures the family revocation
     * commits even though we then throw to the caller.
     */
    @Override
    @Transactional(noRollbackFor = TokenReuseDetectedException.class)
    public AuthenticatedSession rotate(String rawRefreshToken, ClientContext client) {
        Instant now = clock.instant();
        UserSession current = sessionRepository
                .findByRefreshTokenHashForUpdate(tokenService.hashRefreshToken(rawRefreshToken))
                .orElseThrow(() -> new InvalidTokenException("refresh token not recognised"));

        UUID userId = current.getUser().getId();
        if (current.isRevoked()) {
            if (current.getRevocationReason() == RevocationReason.ROTATED) {
                sessionRepository.revokeFamily(current.getFamilyId(), RevocationReason.REUSE_DETECTED, now);
                log.warn("Refresh token reuse detected; token family revoked (userId={}, familyId={})",
                        userId, current.getFamilyId());
                throw new TokenReuseDetectedException(userId);
            }
            log.warn("Refresh rejected: token already revoked (userId={}, reason={})",
                    userId, current.getRevocationReason());
            throw new InvalidTokenException("refresh token revoked: " + current.getRevocationReason());
        }
        if (current.isFamilyExpired(now)) {
            current.revoke(RevocationReason.SESSION_EXPIRED, now);
            log.warn("Refresh rejected: session reached absolute lifetime (userId={}, familyId={})",
                    userId, current.getFamilyId());
            throw new InvalidTokenException("session reached its absolute lifetime");
        }
        if (current.isExpired(now)) {
            log.warn("Refresh rejected: refresh token expired (userId={})", userId);
            throw new InvalidTokenException("refresh token expired");
        }

        User user = userRepository.findWithRolesById(userId)
                .orElseThrow(() -> new InvalidTokenException("session user no longer exists"));
        if (!user.canAuthenticate(now)) {
            current.revoke(RevocationReason.ACCOUNT_INACTIVE, now);
            log.warn("Refresh rejected: account can no longer authenticate (userId={})", userId);
            throw new InvalidTokenException("account can no longer authenticate");
        }

        current.revoke(RevocationReason.ROTATED, now);
        IssuedTokens tokens = issueInFamily(user, current.getFamilyId(), current.getFamilyExpiresAt(), client);
        log.debug("Refresh token rotated (userId={}, familyId={})", userId, current.getFamilyId());
        return new AuthenticatedSession(user, tokens);
    }

    @Override
    @Transactional
    public void revokeByAccessTokenJti(String jti, RevocationReason reason) {
        sessionRepository.revokeByAccessTokenJti(jti, reason, clock.instant());
        log.info("Session revoked by access-token JTI (reason={})", reason);
    }

    @Override
    @Transactional
    public void revokeAllForUser(UUID userId, RevocationReason reason) {
        sessionRepository.revokeAllActiveForUser(userId, reason, clock.instant());
        log.info("All active sessions revoked (userId={}, reason={})", userId, reason);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccessTokenActive(String jti) {
        return sessionRepository.existsByAccessTokenJtiAndRevokedAtIsNull(jti);
    }

    /**
     * Keeps at most maxActiveSessions logins per user by closing the oldest. Bounds how many
     * stolen-but-unnoticed sessions can exist, and keeps the session table small.
     */
    private void enforceSessionLimit(UUID userId, Instant now) {
        List<UserSession> active = sessionRepository.findByUser_IdAndRevokedAtIsNullAndExpiresAtAfterOrderByCreatedAtAsc(userId, now);
        int excess = active.size() - jwtProperties.maxActiveSessions() + 1;   // +1 for the session about to open
        if (excess > 0) {
            log.info("Active-session limit reached; evicting oldest sessions (userId={}, active={}, maxActive={}, evicting={})",
                    userId, active.size(), jwtProperties.maxActiveSessions(), excess);
        }
        for (int i = 0; i < excess; i++) {
            active.get(i).revoke(RevocationReason.SESSION_LIMIT, now);
        }
    }

    private IssuedTokens issueInFamily(User user, UUID familyId, Instant familyExpiresAt, ClientContext client) {
        Instant now = clock.instant();
        String jti = UUID.randomUUID().toString();
        AccessToken accessToken = tokenService.issueAccessToken(user, jti, now);
        String refreshToken = tokenService.newRefreshToken();
        // A refresh token never outlives its login's absolute lifetime
        Instant refreshExpiresAt = min(now.plus(jwtProperties.refreshTokenTtl()), familyExpiresAt);

        UserSession session = UserSession.open(
                userRepository.getReferenceById(user.getId()),
                familyId,
                jti,
                tokenService.hashRefreshToken(refreshToken),
                client,
                min(accessToken.expiresAt(), familyExpiresAt),
                refreshExpiresAt,
                familyExpiresAt);
        sessionRepository.save(session);

        return new IssuedTokens(accessToken.value(), accessToken.expiresAt(), refreshToken, refreshExpiresAt);
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }
}