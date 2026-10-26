package com.pay.auth.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * @param accessTokenTtl      lifetime of one access token (e.g. 15m)
 * @param refreshTokenTtl     lifetime of one refresh token (e.g. 7d); each rotation issues a new one
 * @param sessionAbsoluteTtl  hard cap on a whole login, however often it is refreshed (e.g. 30d)
 * @param maxActiveSessions   concurrent logins per user; the oldest is closed when exceeded
 */
@Validated
@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration refreshTokenTtl,
        @NotNull Duration sessionAbsoluteTtl,
        @Min(1) int maxActiveSessions) {
}
