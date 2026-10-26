package com.banffpay.auth.security;

import com.pay.auth.security.ratelimit.InMemoryRateLimiter;
import com.pay.auth.security.ratelimit.RateLimitDecision;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryRateLimiterTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-10-25T10:00:10Z"), ZoneOffset.UTC);
    private final InMemoryRateLimiter limiter = new InMemoryRateLimiter(clock);

    @Test
    void allowsUpToTheLimitThenRejectsWithRetryAfter() {
        for (int i = 0; i < 3; i++) {
            assertThat(limiter.tryAcquire("login:10.0.0.1", 3, Duration.ofMinutes(1)).allowed()).isTrue();
        }
        RateLimitDecision fourth = limiter.tryAcquire("login:10.0.0.1", 3, Duration.ofMinutes(1));
        assertThat(fourth.allowed()).isFalse();
        assertThat(fourth.retryAfterSeconds()).isEqualTo(50);   // window ends at 10:01:00
    }

    @Test
    void countsEachClientSeparately() {
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire("login:10.0.0.1", 3, Duration.ofMinutes(1));
        }
        assertThat(limiter.tryAcquire("login:10.0.0.2", 3, Duration.ofMinutes(1)).allowed()).isTrue();
    }
}

