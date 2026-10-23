package com.pay.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.pay.auth.config.properties.AdminBootstrapProperties;
import com.pay.auth.exception.StartupConfigurationException;
import com.pay.auth.service.UserAdministrationService;
import com.pay.auth.util.MaskingUtil;

/**
 * Creates the first administrator from environment-supplied credentials.
 * Admins can never self-register: public signup always yields ROLE_USER.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrapRunner implements ApplicationRunner {

    private static final int MIN_ADMIN_PASSWORD_LENGTH = 16;

    private final AdminBootstrapProperties properties;
    private final UserAdministrationService userAdministrationService;

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.enabled()) {
            return;
        }
        if (!StringUtils.hasText(properties.email()) || !StringUtils.hasText(properties.password())) {
            throw new StartupConfigurationException("Admin bootstrap is enabled but the admin email or password is not set.",
                    "Set ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD, or set app.bootstrap.admin.enabled=false.");
        }
        if (properties.password().length() < MIN_ADMIN_PASSWORD_LENGTH) {
            throw new StartupConfigurationException("The bootstrap admin password is shorter than " + MIN_ADMIN_PASSWORD_LENGTH + " characters.",
                    "Set ADMIN_BOOTSTRAP_PASSWORD to at least " + MIN_ADMIN_PASSWORD_LENGTH + " characters.");
        }
        boolean created = userAdministrationService.ensureBootstrapAdmin(
                properties.email(), properties.password(), properties.firstName(), properties.lastName());
        log.info(created ? "Bootstrap administrator created: {}" : "Bootstrap administrator already present: {}",
                MaskingUtil.maskEmail(properties.email()));
    }
}