package com.pay.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;

import com.pay.auth.config.properties.AsyncProperties;
import com.pay.auth.util.MdcTaskDecorator;

/**
 * Virtual-thread executor for fire-and-forget I/O (audit persistence).
 * <p>
 * Virtual threads are never pooled, so instead of a pool size we apply a concurrency
 * limit: once reached, the submitting (virtual) request thread parks cheaply rather than
 * flooding the JDBC pool. MDC is propagated so async logs keep the correlation id.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    public static final String AUDIT_EXECUTOR = "auditExecutor";

    @Bean(name = AUDIT_EXECUTOR)
    public AsyncTaskExecutor auditExecutor(AsyncProperties properties) {
        SimpleAsyncTaskExecutor executor = new SimpleAsyncTaskExecutor("audit-vt-");
        executor.setVirtualThreads(true);
        executor.setConcurrencyLimit(properties.auditConcurrencyLimit());
        executor.setTaskDecorator(new MdcTaskDecorator());
        executor.setTaskTerminationTimeout(5_000);
        return executor;
    }
}
