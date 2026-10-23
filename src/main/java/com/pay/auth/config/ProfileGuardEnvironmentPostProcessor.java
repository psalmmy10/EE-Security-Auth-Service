package com.pay.auth.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

import com.pay.auth.exception.StartupConfigurationException;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Fail-fast guard that runs before any bean is created (after the application*.properties files are loaded).
 * <ul>
 *   <li>Exactly one of dev / staging / prod must be active.</li>
 *   <li>staging/prod may never run with dev-only shortcuts (ephemeral keys, E2E off,
 *       http issuer, localhost or wildcard CORS).</li>
 * </ul>
 * Failures are reported by {@link StartupFailureAnalyzer} as a clean Description / Action message.
 */
public class ProfileGuardEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final Set<String> ENVIRONMENTS = Set.of("dev", "staging", "prod");
    private static final Set<String> HARDENED = Set.of("staging", "prod");

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String[] allActive = environment.getActiveProfiles();
        List<String> active = Arrays.stream(allActive).filter(ENVIRONMENTS::contains).toList();

        if (active.isEmpty()) {
            throw new StartupConfigurationException(
                    "No environment profile is active. Currently active profiles: " + Arrays.toString(allActive),
                    "Set exactly one of dev, staging or prod:\n"
                            + "  - locally:  spring.profiles.active=dev  in application.properties\n"
                            + "  - servers:  SPRING_PROFILES_ACTIVE=staging (or prod) as an environment variable");
        }
        if (active.size() > 1) {
            throw new StartupConfigurationException(
                    "More than one environment profile is active: " + active,
                    "Activate exactly one of dev, staging or prod.");
        }

        String profile = active.get(0);
        if (!HARDENED.contains(profile)) {
            return;
        }

        require("keystore".equals(environment.getProperty("app.security.keys.source")),
                profile + " must use real keys, but app.security.keys.source is '"
                        + environment.getProperty("app.security.keys.source") + "'.",
                "Set app.security.keys.source=keystore and provide KEYSTORE_LOCATION and KEYSTORE_PASSWORD.");

        require(Boolean.TRUE.equals(environment.getProperty("app.security.e2e.enabled", Boolean.class)),
                profile + " cannot run with end-to-end encryption disabled.",
                "Set app.security.e2e.enabled=true (disabling it is allowed in dev only).");

        String issuer = environment.getProperty("app.security.jwt.issuer", "");
        require(issuer.startsWith("https://"),
                profile + " requires an https:// JWT issuer, but it is '" + issuer + "'.",
                "Set the JWT_ISSUER environment variable, e.g. JWT_ISSUER=https://auth.banffpay.com");

        String origins = environment.getProperty("app.cors.allowed-origins", "");
        require(!origins.isBlank() && !origins.contains("localhost") && !origins.contains("127.0.0.1")
                        && !origins.contains("*") && !origins.contains("http://"),
                profile + " requires explicit https:// CORS origins, but they are '" + origins + "'.",
                "Set CORS_ALLOWED_ORIGINS, e.g. CORS_ALLOWED_ORIGINS=https://app.banffpay.com");
    }

    private static void require(boolean condition, String description, String action) {
        if (!condition) {
            throw new StartupConfigurationException("Refusing to start: " + description, action);
        }
    }

    /** After ConfigDataEnvironmentPostProcessor, so profile files are already loaded. */
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}