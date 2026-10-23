package com.pay.auth.config.properties;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.async")
public record AsyncProperties(@Min(1) int auditConcurrencyLimit) {
}
