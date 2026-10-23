package com.pay.auth.event;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import com.pay.auth.config.AsyncConfig;
import com.pay.auth.service.AuditService;

/**
 * Persists audit events on a virtual thread so the login path never waits on audit I/O.
 * For regulator-grade guarantees, swap to a transactional outbox (see README).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditEventListener {

    private final AuditService auditService;

    @Async(AsyncConfig.AUDIT_EXECUTOR)
    @EventListener
    public void onAuthEvent(AuthAuditEvent event) {
        try {
            auditService.record(event);
        } catch (RuntimeException ex) {
            log.error("Failed to persist audit event type={} userId={}", event.type(), event.userId(), ex);
        }
    }
}
