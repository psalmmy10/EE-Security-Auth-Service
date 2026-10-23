package com.pay.auth.config;


import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

import com.pay.auth.exception.StartupConfigurationException;

/**
 * Prints configuration failures as a clean Description / Action report.
 * Works even when the exception is wrapped (e.g. inside a BeanCreationException),
 * because AbstractFailureAnalyzer searches the whole cause chain.
 * Registered in META-INF/spring.factories.
 */
public class StartupFailureAnalyzer extends AbstractFailureAnalyzer<StartupConfigurationException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, StartupConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(), cause.getAction(), cause);
    }
}
