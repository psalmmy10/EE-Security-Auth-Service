package com.pay.auth.security.ratelimit;

import java.time.Duration;

/** Strategy: in-memory for one instance, Redis when several instances must share counters. */
public interface RateLimiter {

    RateLimitDecision tryAcquire(String key, int limit, Duration window);
}

