package com.pay.auth.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.security.lockout")
public record LockoutProperties(@Min(1) int maxAttempts, @NotNull Duration lockDuration) {
}
