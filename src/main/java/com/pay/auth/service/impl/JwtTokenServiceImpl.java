package com.pay.auth.service.impl;

import com.nimbusds.jose.jwk.RSAKey;
import com.pay.auth.config.properties.JwtProperties;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.dao.entity.User;
import com.pay.auth.model.AccessToken;
import com.pay.auth.service.TokenService;
import com.pay.auth.util.CryptoUtil;
import com.pay.auth.util.HashUtil;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * JWTs are signed, not encrypted — anyone holding one can read it. So the token carries only
 * an opaque subject (UUID), the jti and authorities. No email, name or other PII.
 */
@Service
@RequiredArgsConstructor
public class JwtTokenServiceImpl implements TokenService {

    private static final int REFRESH_TOKEN_BYTES = 32;

    private final JwtEncoder jwtEncoder;
    private final RSAKey jwtSigningKey;
    private final JwtProperties jwtProperties;

    @Override
    public AccessToken issueAccessToken(User user, String jti, Instant issuedAt) {
        Instant expiresAt = issuedAt.plus(jwtProperties.accessTokenTtl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .audience(List.of(jwtProperties.audience()))
                .subject(user.getId().toString())
                .issuedAt(issuedAt)
                .notBefore(issuedAt)
                .expiresAt(expiresAt)
                .id(jti)
                .claim(SecurityConstants.CLAIM_AUTHORITIES, user.grantedAuthorities())
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(jwtSigningKey.getKeyID()).build();
        String value = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new AccessToken(value, expiresAt);
    }

    @Override
    public String newRefreshToken() {
        return CryptoUtil.randomUrlSafeToken(REFRESH_TOKEN_BYTES);
    }

    @Override
    public String hashRefreshToken(String rawRefreshToken) {
        return HashUtil.sha256Hex(rawRefreshToken);
    }
}
