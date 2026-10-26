package com.pay.auth.security.ratelimit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;

/**
 * Fixed-window counter shared by all instances: INCR, and set the expiry on the first hit.
 * Fails OPEN if Redis is down (login stays available); per-account lockout still applies.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app.security", name = "state-store", havingValue = "redis")
public class RedisRateLimiter implements RateLimiter {

    private static final String PREFIX = "auth:rl:";

    private final StringRedisTemplate redis;
    private final Clock clock;

    @Override
    public RateLimitDecision tryAcquire(String key, int limit, Duration window) {
        long now = clock.millis();
        long size = window.toMillis();
        long windowStart = now - (now % size);
        String redisKey = PREFIX + key + ":" + windowStart;
        try {
            Long count = redis.opsForValue().increment(redisKey);
            if (count != null && count == 1L) {
                redis.expire(redisKey, window.plusSeconds(1));
            }
            if (count == null || count <= limit) {
                return RateLimitDecision.allow();
            }
            return new RateLimitDecision(false, Math.max(1, (windowStart + size - now + 999) / 1000));
        } catch (DataAccessException ex) {
            log.error("Redis unavailable for rate limiting; allowing request (fail open)", ex);
            return RateLimitDecision.allow();
        }
    }
}

