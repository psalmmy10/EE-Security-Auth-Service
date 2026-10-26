package com.pay.auth.security;

import com.pay.auth.constant.enums.UserStatus;
import com.pay.auth.dao.entity.User;

// import com.pay.auth.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Clock;
import java.util.Collection;

/**
 * Adapter: exposes our User entity to Spring Security as UserDetails.
 * After a successful authenticate(), the service reads the entity back via user().
 */
public final class UserPrincipal implements UserDetails {

    private final User user;
    private final Clock clock;

    public UserPrincipal(User user, Clock clock) {
        this.user = user;
        this.clock = clock;
    }

    public User user() {
        return user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.grantedAuthorities().stream().map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isTemporarilyLocked(clock.instant()) && user.getStatus() != UserStatus.LOCKED;
    }

    @Override
    public boolean isEnabled() {
        return user.getStatus() != UserStatus.DISABLED;
    }

    @Override
    public String toString() {
        return "UserPrincipal[id=" + user.getId() + ", password=****]";
    }
}