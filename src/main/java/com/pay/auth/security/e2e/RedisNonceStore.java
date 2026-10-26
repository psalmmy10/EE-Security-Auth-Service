package com.pay.auth.security.e2e;

import com.pay.auth.util.HashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Replay protection shared by ALL instances (app.security.state-store=redis).
 * SET key NX PX ttl is atomic, so two instances can never both accept the same nonce.
 * Fails CLOSED: if Redis is unreachable, encrypted requests are rejected rather than unprotected.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app.security", name = "state-store", havingValue = "redis")
public class RedisNonceStore implements NonceStore {

    private static final String PREFIX = "auth:e2e:nonce:";

    private final StringRedisTemplate redis;

    @Override
    public boolean registerIfAbsent(String nonce, Duration ttl) {
        try {
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(PREFIX + HashUtil.sha256Hex(nonce), "1", ttl));
        } catch (DataAccessException ex) {
            log.error("Redis unavailable for replay protection; rejecting request (fail closed)", ex);
            return false;
        }
    }
}
