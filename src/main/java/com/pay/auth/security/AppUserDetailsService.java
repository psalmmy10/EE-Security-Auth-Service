package com.pay.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pay.auth.dao.repository.UserRepository;

import java.time.Clock;

/**
 * Loads users for Spring's DaoAuthenticationProvider (user + roles + permissions in one query)
 * and wraps the entity in a UserPrincipal, so Spring Security never works with the entity directly.
 * Also implements UserDetailsPasswordService: when the BCrypt strength is raised, Spring re-hashes
 * a user's password transparently at their next successful login.
 */
@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserRepository userRepository;
    private final Clock clock;

    @Override
    public UserDetails loadUserByUsername(String email) {
        return userRepository.findWithRolesByEmail(email)
                .map(user -> new UserPrincipal(user, clock))
                .orElseThrow(() -> new UsernameNotFoundException("unknown principal"));
    }

    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails details, String newPasswordHash) {
        UserPrincipal principal = (UserPrincipal) details;
        userRepository.updatePasswordHash(principal.user().getId(), newPasswordHash, clock.instant());
        return loadUserByUsername(principal.getUsername());
    }
}