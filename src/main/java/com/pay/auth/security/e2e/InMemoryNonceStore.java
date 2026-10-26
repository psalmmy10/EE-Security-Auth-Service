package com.pay.auth.security.e2e;

import com.pay.auth.config.properties.E2EProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Lock-free (ConcurrentHashMap, no synchronized → no virtual-thread pinning).
 * Bounded to prevent memory exhaustion; fails CLOSED when full.
 * Correct for ONE instance only — with several instances use app.security.state-store=redis.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "app.security", name = "state-store", havingValue = "memory", matchIfMissing = true)
public class InMemoryNonceStore implements NonceStore {

    private final ConcurrentMap<String, Instant> seen = new ConcurrentHashMap<>();
    private final Clock clock;
    private final int maxEntries;

    public InMemoryNonceStore(Clock clock, E2EProperties properties) {
        this.clock = clock;
        this.maxEntries = properties.maxTrackedNonces();
    }

    @Override
    public boolean registerIfAbsent(String nonce, Duration ttl) {
        if (seen.size() >= maxEntries) {
            evictExpired();
            if (seen.size() >= maxEntries) {
                log.warn("Nonce store at capacity ({}); rejecting request", maxEntries);
                return false;
            }
        }
        return seen.putIfAbsent(nonce, clock.instant().plus(ttl)) == null;
    }

    @Scheduled(fixedDelayString = "PT30S")
    public void evictExpired() {
        Instant now = clock.instant();
        seen.values().removeIf(expiry -> expiry.isBefore(now));
    }
}
