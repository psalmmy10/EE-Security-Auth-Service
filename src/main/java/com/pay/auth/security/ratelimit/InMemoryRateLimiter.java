package com.pay.auth.security.ratelimit;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Fixed-window counter per key. Lock-free (no virtual-thread pinning). Single instance only. */
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app.security", name = "state-store", havingValue = "memory", matchIfMissing = true)
public class InMemoryRateLimiter implements RateLimiter {

    private record Window(long expiresAt, AtomicInteger count) {
    }

    private final ConcurrentMap<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    @Override
    public RateLimitDecision tryAcquire(String key, int limit, Duration window) {
        long now = clock.millis();
        long size = window.toMillis();
        long windowStart = now - (now % size);
        long windowEnd = windowStart + size;
        Window current = windows.computeIfAbsent(key + ":" + windowStart, k -> new Window(windowEnd, new AtomicInteger()));
        if (current.count().incrementAndGet() <= limit) {
            return RateLimitDecision.allow();
        }
        return new RateLimitDecision(false, Math.max(1, (windowEnd - now + 999) / 1000));
    }

    @Scheduled(fixedDelayString = "PT30S")
    public void evictExpired() {
        long now = clock.millis();
        windows.values().removeIf(w -> w.expiresAt() < now);
    }
}

