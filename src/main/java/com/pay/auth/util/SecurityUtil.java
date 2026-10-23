package com.pay.auth.util;

import org.springframework.security.oauth2.jwt.Jwt;

import com.pay.auth.exception.InvalidTokenException;

import java.util.UUID;

public final class SecurityUtil {

    private SecurityUtil() {
    }

    public static UUID userId(Jwt jwt) {
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new InvalidTokenException("token subject is not a valid user id");
        }
    }
}
