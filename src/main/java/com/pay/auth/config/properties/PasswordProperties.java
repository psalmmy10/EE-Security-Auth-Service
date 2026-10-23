package com.pay.auth.config.properties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.security.password")
public record PasswordProperties(
        @Min(10) @Max(14) int bcryptStrength,
        @Min(0) int maxConcurrentHashes,
        @NotNull Duration acquireTimeout) {

    public int effectiveConcurrency() {
        return maxConcurrentHashes > 0 ? maxConcurrentHashes : Runtime.getRuntime().availableProcessors();
    }
}
