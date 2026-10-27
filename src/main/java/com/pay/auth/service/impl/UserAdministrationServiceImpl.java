package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pay.auth.constant.enums.AuditEventType;
import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.constant.enums.UserStatus;
import com.pay.auth.dao.entity.Role;
import com.pay.auth.dao.entity.User;
import com.pay.auth.dao.repository.RoleRepository;
import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dto.req.UpdateUserStatusRequest;
import com.pay.auth.dto.res.PageResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.event.AuthAuditEvent;
import com.pay.auth.exception.OperationNotAllowedException;
import com.pay.auth.exception.ResourceNotFoundException;
import com.pay.auth.mapper.UserMapper;
import com.pay.auth.model.ClientContext;
import com.pay.auth.service.SessionService;
import com.pay.auth.service.UserAdministrationService;

import java.time.Clock;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Any change to status or roles revokes the target's sessions, so stale authorities in
 * already-issued JWTs stop working immediately rather than at expiry.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserAdministrationServiceImpl implements UserAdministrationService {

    private static final Sort DEFAULT_SORT = Sort.by(Sort.Direction.DESC, "createdAt");

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final SessionService sessionService;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /** Sort is fixed server-side: clients cannot sort on arbitrary (e.g. hash) columns. */
    @Override
    @Transactional(readOnly = true)
    public PageResponse<UserResponse> listUsers(int page, int size) {
        PageResponse<UserResponse> result = PageResponse.from(
                userRepository.findAll(PageRequest.of(page, size, DEFAULT_SORT)).map(userMapper::toResponse));
        log.debug("Listed users (page={}, size={}, returned={})", page, size, result.content().size());
        return result;
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUser(UUID userId) {
        UserResponse response = userMapper.toResponse(load(userId));
        log.debug("Fetched user (userId={})", userId);
        return response;
    }

    @Override
    @Transactional
    public UserResponse updateStatus(UUID actorId, UUID userId, UpdateUserStatusRequest request, ClientContext client) {
        if (actorId.equals(userId)) {
            log.warn("Status change rejected: administrator attempted to change own status (actorId={})", actorId);
            throw new OperationNotAllowedException("administrators cannot change their own status");
        }
        User user = load(userId);
        UserStatus previous = user.getStatus();
        user.changeStatus(request.status());
        if (request.status() != UserStatus.ACTIVE) {
            sessionService.revokeAllForUser(userId, RevocationReason.ACCOUNT_INACTIVE);
        }
        publish(AuditEventType.USER_STATUS_CHANGED, user, client,
                "from=" + previous + " to=" + request.status() + " by=" + actorId);
        log.info("User status changed (userId={}, from={}, to={}, actorId={})",
                userId, previous, request.status(), actorId);
        return userMapper.toResponse(user);
    }

    @Override
    @Transactional
    public UserResponse assignRole(UUID actorId, UUID userId, RoleName roleName, ClientContext client) {
        User user = load(userId);
        if (user.hasRole(roleName)) {
            log.debug("Assign role skipped: user already has role (userId={}, role={})", userId, roleName);
            return userMapper.toResponse(user);
        }
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("role " + roleName));
        user.assignRole(role);
        sessionService.revokeAllForUser(userId, RevocationReason.ROLE_CHANGED);
        publish(AuditEventType.ROLE_ASSIGNED, user, client, "role=" + roleName + " by=" + actorId);
        log.info("Role assigned (userId={}, role={}, actorId={})", userId, roleName, actorId);
        return userMapper.toResponse(user);
    }

    @Override
    @Transactional
    public UserResponse revokeRole(UUID actorId, UUID userId, RoleName roleName, ClientContext client) {
        if (actorId.equals(userId) && roleName == RoleName.ADMIN) {
            log.warn("Role revoke rejected: administrator attempted to revoke own ADMIN role (actorId={})", actorId);
            throw new OperationNotAllowedException("administrators cannot revoke their own ADMIN role");
        }
        User user = load(userId);
        if (!user.hasRole(roleName)) {
            log.debug("Revoke role skipped: user does not have role (userId={}, role={})", userId, roleName);
            return userMapper.toResponse(user);
        }
        if (user.getRoles().size() == 1) {
            log.warn("Role revoke rejected: user must retain at least one role (userId={}, role={}, actorId={})",
                    userId, roleName, actorId);
            throw new OperationNotAllowedException("a user must retain at least one role");
        }
        user.revokeRole(roleName);
        sessionService.revokeAllForUser(userId, RevocationReason.ROLE_CHANGED);
        publish(AuditEventType.ROLE_REVOKED, user, client, "role=" + roleName + " by=" + actorId);
        log.info("Role revoked (userId={}, role={}, actorId={})", userId, roleName, actorId);
        return userMapper.toResponse(user);
    }

    /** Startup-only path, so hashing inside the transaction is acceptable here. */
    @Override
    @Transactional
    public boolean ensureBootstrapAdmin(String email, String rawPassword, String firstName, String lastName) {
        String normalised = email.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalised)) {
            log.info("Bootstrap admin skipped: user already exists (email={})", normalised);
            return false;
        }
        Role userRole = roleRepository.findByName(RoleName.USER).orElseThrow(() -> new IllegalStateException("USER role missing"));
        Role adminRole = roleRepository.findByName(RoleName.ADMIN).orElseThrow(() -> new IllegalStateException("ADMIN role missing"));
        User admin = userRepository.save(User.register(normalised, passwordEncoder.encode(rawPassword),
                firstName, lastName, Set.of(userRole, adminRole)));
        publish(AuditEventType.ADMIN_BOOTSTRAPPED, admin, null, null);
        log.info("Bootstrap admin created (userId={}, email={})", admin.getId(), normalised);
        return true;
    }

    private User load(UUID userId) {
        return userRepository.findWithRolesById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user " + userId));
    }

    private void publish(AuditEventType type, User user, ClientContext client, String detail) {
        events.publishEvent(AuthAuditEvent.of(type, user.getId(), user.getEmail(), client, detail, clock.instant()));
    }
}