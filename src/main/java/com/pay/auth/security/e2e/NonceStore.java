package com.pay.auth.security.e2e;

import java.time.Duration;

/**
 * Replay-protection store. The in-memory implementation is correct for a single node;
 * for horizontal scaling provide a Redis implementation (SET key NX PX ttl).
 */
public interface NonceStore {

    /** @return true if the nonce was unseen and is now recorded; false if it is a replay. */
    boolean registerIfAbsent(String nonce, Duration ttl);
}
