package com.pay.auth.service.impl;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.constant.enums.AuditEventType;
import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.constant.enums.UserStatus;
import com.pay.auth.dao.entity.Role;
import com.pay.auth.dao.entity.User;
import com.pay.auth.dao.repository.RoleRepository;
import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dto.req.LoginRequest;
import com.pay.auth.dto.req.RefreshTokenRequest;
import com.pay.auth.dto.req.SignupRequest;
import com.pay.auth.dto.res.AuthResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.event.AuthAuditEvent;
import com.pay.auth.exception.AccountInactiveException;
import com.pay.auth.exception.AccountLockedException;
import com.pay.auth.exception.AuthenticationFailedException;
import com.pay.auth.exception.RegistrationConflictException;
import com.pay.auth.exception.TokenReuseDetectedException;
import com.pay.auth.mapper.UserMapper;
import com.pay.auth.model.AuthenticatedSession;
import com.pay.auth.model.ClientContext;
import com.pay.auth.model.IssuedTokens;
import com.pay.auth.service.AuthService;
import com.pay.auth.service.LoginAttemptService;
import com.pay.auth.service.SessionService;
import com.pay.auth.util.CryptoUtil;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Orchestrates authentication flows.
 * <p>
 * Connection-pool discipline (important with virtual threads): BCrypt runs OUTSIDE any
 * transaction, so a ~250 ms CPU-bound hash never holds one of the 20 pooled JDBC connections.
 * Short transactions are opened explicitly with {@link TransactionTemplate} only around DB work.
 */
@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final LoginAttemptService loginAttemptService;
    private final UserMapper userMapper;
    private final ApplicationEventPublisher events;
    private final TransactionTemplate transactionTemplate;
    private final Clock clock;

    /** Compared against when the email is unknown, so both paths cost one BCrypt verification. */
    private final String timingEqualisationHash;

    public AuthServiceImpl(UserRepository userRepository, RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder, SessionService sessionService,
                           LoginAttemptService loginAttemptService, UserMapper userMapper,
                           ApplicationEventPublisher events, TransactionTemplate transactionTemplate, Clock clock) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.loginAttemptService = loginAttemptService;
        this.userMapper = userMapper;
        this.events = events;
        this.transactionTemplate = transactionTemplate;
        this.clock = clock;
        this.timingEqualisationHash = passwordEncoder.encode(CryptoUtil.randomUrlSafeToken(24));
    }

    @Override
    public UserResponse signup(SignupRequest request, ClientContext client) {
        String email = normaliseEmail(request.email());
        // Hash first, even for duplicate emails: equal timing, and no connection held while hashing.
        String passwordHash = passwordEncoder.encode(request.password());
        User saved = transactionTemplate.execute(status -> persistNewUser(email, passwordHash, request));
        publish(AuditEventType.SIGNUP_SUCCESS, saved.getId(), email, client, null);
        return userMapper.toResponse(saved);
    }

    @Override
    public AuthResponse login(LoginRequest request, ClientContext client) {
        String email = normaliseEmail(request.email());
        Optional<User> candidate = userRepository.findWithRolesByEmail(email);

        if (candidate.isEmpty()) {
            passwordEncoder.matches(request.password(), timingEqualisationHash);
            publish(AuditEventType.LOGIN_FAILURE, null, email, client, "unknown principal");
            throw new AuthenticationFailedException("unknown principal");
        }

        User user = candidate.get();
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            boolean lockedNow = loginAttemptService.recordFailure(user.getId());
            publish(AuditEventType.LOGIN_FAILURE, user.getId(), email, client, "bad credentials");
            if (lockedNow) {
                publish(AuditEventType.ACCOUNT_LOCKED, user.getId(), email, client, "failed-attempt threshold reached");
            }
            throw new AuthenticationFailedException("bad credentials");
        }

        // Account state is only revealed to someone who already proved knowledge of the password.
        assertCanAuthenticate(user, clock.instant());
        loginAttemptService.recordSuccess(user.getId());
        IssuedTokens tokens = sessionService.openSession(user, client);
        publish(AuditEventType.LOGIN_SUCCESS, user.getId(), email, client, null);
        return toAuthResponse(user, tokens);
    }

    @Override
    public AuthResponse refresh(RefreshTokenRequest request, ClientContext client) {
        try {
            AuthenticatedSession session = sessionService.rotate(request.refreshToken(), client);
            publish(AuditEventType.TOKEN_REFRESHED, session.user().getId(), session.user().getEmail(), client, null);
            return toAuthResponse(session.user(), session.tokens());
        } catch (TokenReuseDetectedException ex) {
            publish(AuditEventType.TOKEN_REUSE_DETECTED, ex.getUserId(), null, client, "token family revoked");
            throw ex;
        }
    }

    @Override
    public void logout(UUID userId, String accessTokenJti, ClientContext client) {
        sessionService.revokeByAccessTokenJti(accessTokenJti, RevocationReason.LOGOUT);
        publish(AuditEventType.LOGOUT, userId, null, client, null);
    }

    @Override
    public void logoutAll(UUID userId, ClientContext client) {
        sessionService.revokeAllForUser(userId, RevocationReason.LOGOUT_ALL);
        publish(AuditEventType.LOGOUT_ALL, userId, null, client, null);
    }

    private User persistNewUser(String email, String passwordHash, SignupRequest request) {
        if (userRepository.existsByEmail(email)) {
            throw new RegistrationConflictException("email already registered");
        }
        Role userRole = roleRepository.findByName(RoleName.USER)
                .orElseThrow(() -> new IllegalStateException("Default USER role missing; check Flyway seed"));
        User user = User.register(email, passwordHash, request.firstName().trim(), request.lastName().trim(), Set.of(userRole));
        try {
            return userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            // Concurrent signup with the same email lost the race against the unique constraint.
            throw new RegistrationConflictException("unique constraint violation on email", ex);
        }
    }

    private void assertCanAuthenticate(User user, Instant now) {
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AccountInactiveException("account status " + user.getStatus());
        }
        if (user.isTemporarilyLocked(now)) {
            throw new AccountLockedException("account locked until " + user.getLockedUntil());
        }
    }

    private AuthResponse toAuthResponse(User user, IssuedTokens tokens) {
        long expiresIn = Math.max(0, Duration.between(clock.instant(), tokens.accessTokenExpiresAt()).toSeconds());
        return new AuthResponse(SecurityConstants.TOKEN_TYPE_BEARER, tokens.accessToken(), tokens.accessTokenExpiresAt(),
                expiresIn, tokens.refreshToken(), tokens.refreshTokenExpiresAt(), userMapper.toResponse(user));
    }

    private void publish(AuditEventType type, UUID userId, String principal, ClientContext client, String detail) {
        events.publishEvent(AuthAuditEvent.of(type, userId, principal, client, detail, clock.instant()));
    }

    static String normaliseEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
