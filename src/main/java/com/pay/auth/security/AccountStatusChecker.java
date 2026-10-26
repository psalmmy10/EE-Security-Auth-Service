package com.pay.auth.security;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

/**
 * Account-status check, run AFTER the password is verified (see AuthenticationConfig).
 * Spring's default runs it BEFORE, which would tell someone without the password that an
 * account exists and is locked or disabled.
 */
public class AccountStatusChecker implements UserDetailsChecker {

    @Override
    public void check(UserDetails user) {
        if (!user.isEnabled()) {
            throw new DisabledException("account disabled");
        }
        if (!user.isAccountNonLocked()) {
            throw new LockedException("account locked");
        }
    }
}