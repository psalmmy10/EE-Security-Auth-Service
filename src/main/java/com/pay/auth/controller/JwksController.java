package com.pay.auth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.pay.auth.constant.ApiPaths;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Standard JWKS (RFC 7517). Only the public half is ever serialised; downstream services set
 * spring.security.oauth2.resourceserver.jwt.jwk-set-uri to this endpoint.
 */
@RestController
public class JwksController {

    private final Map<String, Object> publicJwks;

    public JwksController(RSAKey jwtSigningKey) {
        this.publicJwks = new JWKSet(jwtSigningKey.toPublicJWK()).toJSONObject();
    }

    @GetMapping(value = ApiPaths.JWKS, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        return publicJwks;
    }
}
