package com.pay.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Value;
import java.util.ArrayList;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.pay.auth.config.properties.CorsProperties;
import com.pay.auth.config.properties.PasswordProperties;
import com.pay.auth.constant.ApiPaths;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.security.handler.RestAccessDeniedHandler;
import com.pay.auth.security.handler.RestAuthenticationEntryPoint;

import java.util.List;
import java.util.Map;

/**
 * Stateless OAuth2 resource-server configuration.
 * <ul>
 *   <li>CSRF disabled: no cookies are used; credentials travel only in the Authorization header.</li>
 *   <li>Defence in depth: URL rules guard /admin/** and method security guards each operation.</li>
 *   <li>Strict security headers (HSTS, CSP none, no framing, no referrer).</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${app.security.e2e.swagger-test-enabled:false}")
    private boolean swaggerTestEnabled;

    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;
    private final CorsProperties corsProperties;


    List<String> exposedHeaders = new ArrayList<>(List.of(
                SecurityConstants.HEADER_E2E_ENCRYPTED,
                SecurityConstants.HEADER_CORRELATION_ID
        ));
    

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder,
                                                   JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'none'; frame-ancestors 'none'"
                        ))
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000)))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(SecurityConstants.publicEndpoints()).permitAll()
                        .requestMatchers(ApiPaths.ADMIN + "/**").hasRole(RoleName.ADMIN.name())
                        .anyRequest().authenticated())

                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }

    /** Maps the "authorities" claim 1:1 (ROLE_* and permission names) onto Spring authorities. */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(SecurityConstants.CLAIM_AUTHORITIES);
        authorities.setAuthorityPrefix("");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        converter.setPrincipalClaimName(JwtClaimNames.SUB);
        return converter;
    }

    /**
     * Decorator stack: Bounded(Delegating(BCrypt)). The delegating encoder prefixes hashes
     * with {bcrypt} so the algorithm can be migrated later without a flag day.
     */
    @Bean
    public PasswordEncoder passwordEncoder(PasswordProperties properties) {
        PasswordEncoder delegating = new DelegatingPasswordEncoder("bcrypt",
                Map.<String, PasswordEncoder>of("bcrypt", new BCryptPasswordEncoder(properties.bcryptStrength())));
        return new BoundedPasswordEncoder(delegating, properties.effectiveConcurrency(), properties.acquireTimeout());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(corsProperties.allowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of(
                HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE,
                SecurityConstants.HEADER_E2E_KEY, SecurityConstants.HEADER_E2E_KEY_ID,
                SecurityConstants.HEADER_E2E_TIMESTAMP, SecurityConstants.HEADER_E2E_NONCE,
                SecurityConstants.HEADER_CORRELATION_ID));

        if (swaggerTestEnabled) {
           exposedHeaders.add("X-E2E-Request-Nonce");
        }

        config.setExposedHeaders(
                // List.of(SecurityConstants.HEADER_E2E_ENCRYPTED, SecurityConstants.HEADER_CORRELATION_ID)
                exposedHeaders  
        );
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
