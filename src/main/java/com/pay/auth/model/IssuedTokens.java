package com.pay.auth.model;

import java.time.Instant;

public record IssuedTokens(String accessToken, Instant accessTokenExpiresAt,
                           String refreshToken, Instant refreshTokenExpiresAt) {

    @Override
    public String toString() {
        return "IssuedTokens[accessToken=****, refreshToken=****, accessTokenExpiresAt=" + accessTokenExpiresAt + "]";
    }
}
