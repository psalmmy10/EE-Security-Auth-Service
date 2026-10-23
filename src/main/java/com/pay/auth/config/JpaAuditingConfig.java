package com.pay.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/** Kept separate from the main class so web slice tests don't need JPA. */
@Configuration
@EnableJpaAuditing
public class JpaAuditingConfig {
}
