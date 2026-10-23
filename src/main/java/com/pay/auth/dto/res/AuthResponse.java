package com.pay.auth.dto.res;

import java.time.Instant;

public record AuthResponse(
        String tokenType,
        String accessToken,
        Instant accessTokenExpiresAt,
        long expiresIn,
        String refreshToken,
        Instant refreshTokenExpiresAt,
        UserResponse user) {

    @Override
    public String toString() {
        return "AuthResponse[tokenType=" + tokenType + ", accessToken=****, refreshToken=****, userId="
                + (user == null ? null : user.id()) + "]";
    }
}
