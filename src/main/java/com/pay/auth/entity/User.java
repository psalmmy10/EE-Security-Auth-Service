package com.pay.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.constant.enums.UserStatus;

/**
 * Rich domain entity: state changes go through intention-revealing methods instead of
 * public setters, so invariants (e.g. unlocking on reactivation) live in one place.
 * <p>
 * User &gt;--&lt; Role is many-to-many. Sessions are mapped only from the session side
 * (unidirectional @ManyToOne) so loading a user never drags its session history along.
 * No Lombok @ToString/@Data: the password hash must never reach a log line.
 */
@Getter
@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Column(name = "email", nullable = false, unique = true, length = 150)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public static User register(String email, String passwordHash, String firstName, String lastName, Set<Role> roles) {
        User user = new User();
        user.email = email;
        user.passwordHash = passwordHash;
        user.firstName = firstName;
        user.lastName = lastName;
        user.status = UserStatus.ACTIVE;
        user.failedLoginAttempts = 0;
        user.roles = new HashSet<>(roles);
        return user;
    }

    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public boolean hasRole(RoleName roleName) {
        return roles.stream().anyMatch(role -> role.getName() == roleName);
    }

    public void assignRole(Role role) {
        roles.add(role);
    }

    public void revokeRole(RoleName roleName) {
        roles.removeIf(role -> role.getName() == roleName);
    }

    public void changeStatus(UserStatus newStatus) {
        this.status = newStatus;
        if (newStatus == UserStatus.ACTIVE) {
            this.failedLoginAttempts = 0;
            this.lockedUntil = null;
        }
    }

    public boolean isTemporarilyLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public boolean canAuthenticate(Instant now) {
        return status == UserStatus.ACTIVE && !isTemporarilyLocked(now);
    }

    /** Role authorities (ROLE_*) plus flattened permission names, de-duplicated and sorted. */
    public List<String> grantedAuthorities() {
        Stream<String> roleAuthorities = roles.stream().map(Role::authority);
        Stream<String> permissionAuthorities = roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName().name());
        return Stream.concat(roleAuthorities, permissionAuthorities).distinct().sorted().toList();
    }
}
