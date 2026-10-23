package com.pay.auth.exception;

import lombok.Getter;

/**
 * Thrown when the service cannot start because of a configuration problem the operator must fix.
 * {@link com.pay.auth.config.StartupFailureAnalyzer} turns it into Spring Boot's
 * "APPLICATION FAILED TO START" report (Description + Action) instead of a stack trace.
 */
@Getter
public class StartupConfigurationException extends RuntimeException {

    private final String action;

    public StartupConfigurationException(String description, String action) {
        super(description);
        this.action = action;
    }

    public StartupConfigurationException(String description, String action, Throwable cause) {
        super(description, cause);
        this.action = action;
    }
}