package com.pay.auth.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/** Per-client-IP limits on the unauthenticated, attack-prone endpoints. */
@Validated
@ConfigurationProperties(prefix = "app.security.rate-limit")
public record RateLimitProperties(boolean enabled, @Valid @NotNull Rule login, @Valid @NotNull Rule signup,
                                  @Valid @NotNull Rule refresh) {

    public record Rule(@Min(1) int limit, @NotNull Duration window) {
    }
}
