package com.pay.auth.service.impl;

import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.constant.enums.AuditEventType;
import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.dao.entity.Role;
import com.pay.auth.dao.entity.User;
import com.pay.auth.dao.repository.RoleRepository;
import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dto.req.LoginRequest;
import com.pay.auth.dto.req.RefreshTokenRequest;
import com.pay.auth.dto.req.SignupRequest;
import com.pay.auth.dto.res.AuthResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.security.UserPrincipal;
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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
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
@Slf4j
@Service
@RequiredArgsConstructor
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

    private final AuthenticationManager authenticationManager;


    @SuppressWarnings("null")
    @Override
    public UserResponse signup(SignupRequest request, ClientContext client) {
        String email = normaliseEmail(request.email());
        log.info("Signup request received (email={}, firstName={}, lastName={}, client={})",
                email, maskPii(request.firstName()), maskPii(request.lastName()), client);
                
        // Hash first, even for duplicate emails: equal timing, and no connection held while hashing.
        String passwordHash = passwordEncoder.encode(request.password());

        User saved = transactionTemplate.execute(
                        status -> persistNewUser(email, passwordHash, request)
                    );

        publish(AuditEventType.SIGNUP_SUCCESS, saved.getId(), email, client, null);
        log.info("Signup succeeded (userId={}, email={})", saved.getId(), email);
        return userMapper.toResponse(saved);
    }

    /**
     * Credentials are verified by Spring's AuthenticationManager (see AuthenticationConfig).
     * This method only translates the outcome into lockout bookkeeping, audit events and tokens.
     */
    @Override
    public AuthResponse login(LoginRequest request, ClientContext client) {
        String email = normaliseEmail(request.email());
        log.info("Login request received (email={}, client={})", email, client);
        User user;
        try {
            Authentication result = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(email, request.password()));
            user = ((UserPrincipal) result.getPrincipal()).user();
        } catch (BadCredentialsException ex) {             // unknown email OR wrong password — same response
            recordFailedLogin(email, client);
            throw new AuthenticationFailedException("bad credentials");
        } catch (LockedException ex) {                     // only reachable with the correct password
            log.warn("Login rejected: account locked (email={})", email);
            throw new AccountLockedException("account locked");
        } catch (DisabledException ex) {                   // only reachable with the correct password
            log.warn("Login rejected: account disabled (email={})", email);
            throw new AccountInactiveException("account disabled");
        } catch (InternalAuthenticationServiceException ex) {
            log.error("Authentication backend failure during login (email={})", email, ex);
            throw new IllegalStateException("authentication backend failure", ex.getCause());
        }

        loginAttemptService.recordSuccess(user.getId());
        IssuedTokens tokens = sessionService.openSession(user, client);
        publish(AuditEventType.LOGIN_SUCCESS, user.getId(), email, client, null);
        log.info("Login succeeded (userId={}, email={})", user.getId(), email);
        return toAuthResponse(user, tokens);
    }

    private void recordFailedLogin(String email, ClientContext client) {
        Optional<UUID> userId = userRepository.findIdByEmail(email);
        if (userId.isEmpty()) {
            log.warn("Login failed: unknown principal (email={})", email);
            publish(AuditEventType.LOGIN_FAILURE, null, email, client, "unknown principal");
            return;
        }
        boolean lockedNow = loginAttemptService.recordFailure(userId.get());
        log.warn("Login failed: bad credentials (userId={}, email={})", userId.get(), email);
        publish(AuditEventType.LOGIN_FAILURE, userId.get(), email, client, "bad credentials");
        if (lockedNow) {
            log.warn("Account locked after failed-attempt threshold reached (userId={}, email={})", userId.get(), email);
            publish(AuditEventType.ACCOUNT_LOCKED, userId.get(), email, client, "failed-attempt threshold reached");
        }
    }

    @Override
    public AuthResponse refresh(RefreshTokenRequest request, ClientContext client) {
        // Never log the raw refresh token — only that one was supplied and its length.
        log.info("Refresh request received (client={}, refreshTokenPresent={}",
                client, request.refreshToken() != null);
        try {
            AuthenticatedSession session = sessionService.rotate(request.refreshToken(), client);
            publish(AuditEventType.TOKEN_REFRESHED, session.user().getId(), session.user().getEmail(), client, null);
            log.info("Refresh succeeded (userId={})", session.user().getId());
            return toAuthResponse(session.user(), session.tokens());
        } catch (TokenReuseDetectedException ex) {
            log.warn("Refresh token reuse detected; token family revoked (userId={})", ex.getUserId());
            publish(AuditEventType.TOKEN_REUSE_DETECTED, ex.getUserId(), null, client, "token family revoked");
            throw ex;
        }
    }

    @Override
    public void logout(UUID userId, String accessTokenJti, ClientContext client) {
        // JTIs identify the session but are sensitive — log presence only.
        log.info("Logout request received (userId={}, client={}, accessTokenJtiPresent={})",
                userId, client, accessTokenJti != null);
        sessionService.revokeByAccessTokenJti(accessTokenJti, RevocationReason.LOGOUT);
        publish(AuditEventType.LOGOUT, userId, null, client, null);
        log.info("Logout succeeded (userId={})", userId);
    }

    @Override
    public void logoutAll(UUID userId, ClientContext client) {
        log.info("Logout-all request received (userId={}, client={})", userId, client);
        sessionService.revokeAllForUser(userId, RevocationReason.LOGOUT_ALL);
        publish(AuditEventType.LOGOUT_ALL, userId, null, client, null);
        log.info("Logout-all succeeded (userId={})", userId);
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
            log.warn("Signup lost unique-constraint race on email (email={})", email);
            throw new RegistrationConflictException("unique constraint violation on email", ex);
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

    /** Masks a name for logs, keeping only the first character. */
    private static String maskPii(String value) {
        if (value == null || value.isEmpty()) {
            return "<empty>";
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? "<empty>" : trimmed.charAt(0) + "***";
    }

}