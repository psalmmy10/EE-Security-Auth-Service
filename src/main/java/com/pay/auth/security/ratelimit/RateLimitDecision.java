package com.pay.auth.security.ratelimit;

/** @param retryAfterSeconds seconds until the current window resets (0 when allowed) */
public record RateLimitDecision(boolean allowed, long retryAfterSeconds) {

    public static RateLimitDecision allow() {
        return new RateLimitDecision(true, 0);
    }
}
