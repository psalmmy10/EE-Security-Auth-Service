package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

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
        return issueInFamily(user, UUID.randomUUID(), client);
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
                throw new TokenReuseDetectedException(userId);
            }
            throw new InvalidTokenException("refresh token revoked: " + current.getRevocationReason());
        }
        if (current.isExpired(now)) {
            throw new InvalidTokenException("refresh token expired");
        }

        User user = userRepository.findWithRolesById(userId)
                .orElseThrow(() -> new InvalidTokenException("session user no longer exists"));
        if (!user.canAuthenticate(now)) {
            current.revoke(RevocationReason.ACCOUNT_INACTIVE, now);
            throw new InvalidTokenException("account can no longer authenticate");
        }

        current.revoke(RevocationReason.ROTATED, now);
        IssuedTokens tokens = issueInFamily(user, current.getFamilyId(), client);
        return new AuthenticatedSession(user, tokens);
    }

    @Override
    @Transactional
    public void revokeByAccessTokenJti(String jti, RevocationReason reason) {
        sessionRepository.revokeByAccessTokenJti(jti, reason, clock.instant());
    }

    @Override
    @Transactional
    public void revokeAllForUser(UUID userId, RevocationReason reason) {
        sessionRepository.revokeAllActiveForUser(userId, reason, clock.instant());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccessTokenActive(String jti) {
        return sessionRepository.existsByAccessTokenJtiAndRevokedAtIsNull(jti);
    }

    private IssuedTokens issueInFamily(User user, UUID familyId, ClientContext client) {
        Instant now = clock.instant();
        String jti = UUID.randomUUID().toString();
        AccessToken accessToken = tokenService.issueAccessToken(user, jti, now);
        String refreshToken = tokenService.newRefreshToken();
        Instant refreshExpiresAt = now.plus(jwtProperties.refreshTokenTtl());

        UserSession session = UserSession.open(
                userRepository.getReferenceById(user.getId()),
                familyId,
                jti,
                tokenService.hashRefreshToken(refreshToken),
                client,
                accessToken.expiresAt(),
                refreshExpiresAt);
        sessionRepository.save(session);

        return new IssuedTokens(accessToken.value(), accessToken.expiresAt(), refreshToken, refreshExpiresAt);
    }
}
