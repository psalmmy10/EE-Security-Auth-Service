package com.pay.auth.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.pay.auth.service.SessionService;

/**
 * Makes logout real: a signed, unexpired JWT is still rejected once its session (jti) is revoked.
 * Cost is one indexed lookup per request — cheap on virtual threads; add a short-TTL cache
 * (Caffeine/Redis) if p99 latency demands it.
 */
@Component
@RequiredArgsConstructor
public class ActiveSessionTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INACTIVE =
            new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Token is no longer active", null);

    private final SessionService sessionService;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String jti = jwt.getId();
        if (!StringUtils.hasText(jti) || !sessionService.isAccessTokenActive(jti)) {
            return OAuth2TokenValidatorResult.failure(INACTIVE);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
