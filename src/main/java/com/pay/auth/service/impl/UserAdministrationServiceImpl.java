package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
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
import com.pay.auth.dao.RoleRepository;
import com.pay.auth.dao.UserRepository;
import com.pay.auth.dto.req.UpdateUserStatusRequest;
import com.pay.auth.dto.res.PageResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.entity.Role;
import com.pay.auth.entity.User;
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
        return PageResponse.from(userRepository.findAll(PageRequest.of(page, size, DEFAULT_SORT)).map(userMapper::toResponse));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUser(UUID userId) {
        return userMapper.toResponse(load(userId));
    }

    @Override
    @Transactional
    public UserResponse updateStatus(UUID actorId, UUID userId, UpdateUserStatusRequest request, ClientContext client) {
        if (actorId.equals(userId)) {
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
        return userMapper.toResponse(user);
    }

    @Override
    @Transactional
    public UserResponse assignRole(UUID actorId, UUID userId, RoleName roleName, ClientContext client) {
        User user = load(userId);
        if (user.hasRole(roleName)) {
            return userMapper.toResponse(user);
        }
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("role " + roleName));
        user.assignRole(role);
        sessionService.revokeAllForUser(userId, RevocationReason.ROLE_CHANGED);
        publish(AuditEventType.ROLE_ASSIGNED, user, client, "role=" + roleName + " by=" + actorId);
        return userMapper.toResponse(user);
    }

    @Override
    @Transactional
    public UserResponse revokeRole(UUID actorId, UUID userId, RoleName roleName, ClientContext client) {
        if (actorId.equals(userId) && roleName == RoleName.ADMIN) {
            throw new OperationNotAllowedException("administrators cannot revoke their own ADMIN role");
        }
        User user = load(userId);
        if (!user.hasRole(roleName)) {
            return userMapper.toResponse(user);
        }
        if (user.getRoles().size() == 1) {
            throw new OperationNotAllowedException("a user must retain at least one role");
        }
        user.revokeRole(roleName);
        sessionService.revokeAllForUser(userId, RevocationReason.ROLE_CHANGED);
        publish(AuditEventType.ROLE_REVOKED, user, client, "role=" + roleName + " by=" + actorId);
        return userMapper.toResponse(user);
    }

    /** Startup-only path, so hashing inside the transaction is acceptable here. */
    @Override
    @Transactional
    public boolean ensureBootstrapAdmin(String email, String rawPassword, String firstName, String lastName) {
        String normalised = email.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalised)) {
            return false;
        }
        Role userRole = roleRepository.findByName(RoleName.USER).orElseThrow(() -> new IllegalStateException("USER role missing"));
        Role adminRole = roleRepository.findByName(RoleName.ADMIN).orElseThrow(() -> new IllegalStateException("ADMIN role missing"));
        User admin = userRepository.save(User.register(normalised, passwordEncoder.encode(rawPassword),
                firstName, lastName, Set.of(userRole, adminRole)));
        publish(AuditEventType.ADMIN_BOOTSTRAPPED, admin, null, null);
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
