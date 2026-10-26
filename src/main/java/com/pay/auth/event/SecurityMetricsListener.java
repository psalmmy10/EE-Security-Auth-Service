package com.pay.auth.event;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Turns every security event into a metric: auth.security.events{type=LOGIN_FAILURE|ACCOUNT_LOCKED|TOKEN_REUSE_DETECTED|…}.
 * Alert on spikes (e.g. LOGIN_FAILURE rate, any TOKEN_REUSE_DETECTED) in Prometheus/Grafana.
 * Synchronous on purpose: a counter increment is cheap and must not be lost.
 */
@Component
@RequiredArgsConstructor
public class SecurityMetricsListener {

    private final MeterRegistry meterRegistry;

    @EventListener
    public void onAuthEvent(AuthAuditEvent event) {
        meterRegistry.counter("auth.security.events", "type", event.type().name()).increment();
    }
}
