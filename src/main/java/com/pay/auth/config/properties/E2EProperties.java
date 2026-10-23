package com.pay.auth.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/** enabled=false is permitted only in dev (ProfileGuardEnvironmentPostProcessor). */
@Validated
@ConfigurationProperties(prefix = "app.security.e2e")
public record E2EProperties(boolean enabled, @NotNull Duration replayWindow, @Min(1000) int maxTrackedNonces) {
}