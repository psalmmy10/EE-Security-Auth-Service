package com.pay.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Spring-managed username/password authentication.
 * <ul>
 *   <li>DaoAuthenticationProvider: loads the user, verifies BCrypt, runs a dummy hash for unknown
 *       users (timing-attack protection), and hides "user not found" as bad credentials.</li>
 *   <li>Status checks moved AFTER the password check, so lock/disabled state is never revealed
 *       to someone who doesn't know the password.</li>
 *   <li>Uses our BoundedPasswordEncoder, so hashing stays capped under load.</li>
 * </ul>
 * Separate from the JWT resource-server chain, which keeps its own JwtAuthenticationProvider.
 */
@Configuration
public class AuthenticationConfig {

    @Bean
    public AuthenticationManager authenticationManager(AppUserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setUserDetailsPasswordService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setPreAuthenticationChecks(user -> { });                 // nothing before the password
        provider.setPostAuthenticationChecks(new AccountStatusChecker()); // status only after it
        provider.setHideUserNotFoundExceptions(true);

        ProviderManager manager = new ProviderManager(provider);
        manager.setEraseCredentialsAfterAuthentication(true);
        return manager;
    }
}