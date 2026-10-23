package com.pay.auth.exception;

import lombok.Getter;

import java.util.UUID;

/**
 * A rotated refresh token was replayed: strong signal of token theft. Reported to the
 * client as a plain invalid token so the attacker learns nothing extra.
 */
@Getter
public class TokenReuseDetectedException extends InvalidTokenException {

    private final UUID userId;

    public TokenReuseDetectedException(UUID userId) {
        super("refresh token reuse detected; token family revoked");
        this.userId = userId;
    }
}
