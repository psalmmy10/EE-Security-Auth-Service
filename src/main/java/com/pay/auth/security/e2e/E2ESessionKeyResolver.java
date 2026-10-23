package com.pay.auth.security.e2e;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.pay.auth.config.properties.E2EProperties;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.exception.E2EException;
import com.pay.auth.service.CryptoService;
import com.pay.auth.util.RequestUtil;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Validates E2E headers and establishes the per-request key.
 * Order matters: cheap checks (presence, key id, clock skew, format) run before the RSA
 * private-key operation, and the nonce is only burned once the key unwrap has succeeded.
 */
@Component
@RequiredArgsConstructor
public class E2ESessionKeyResolver {

    private static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9+/=_\\-]{16,88}$");
    private static final int MAX_WRAPPED_KEY_LENGTH = 1024;

    private final CryptoService cryptoService;
    private final NonceStore nonceStore;
    private final E2EProperties properties;
    private final java.time.Clock clock;

    public E2EContext resolve(HttpServletRequest request) {
        String wrappedKey = request.getHeader(SecurityConstants.HEADER_E2E_KEY);
        String keyId = request.getHeader(SecurityConstants.HEADER_E2E_KEY_ID);
        String rawTimestamp = request.getHeader(SecurityConstants.HEADER_E2E_TIMESTAMP);
        String nonce = request.getHeader(SecurityConstants.HEADER_E2E_NONCE);

        List<String> missing = new ArrayList<>();
        if (!StringUtils.hasText(wrappedKey)) missing.add(SecurityConstants.HEADER_E2E_KEY);
        if (!StringUtils.hasText(keyId)) missing.add(SecurityConstants.HEADER_E2E_KEY_ID);
        if (!StringUtils.hasText(rawTimestamp)) missing.add(SecurityConstants.HEADER_E2E_TIMESTAMP);
        if (!StringUtils.hasText(nonce)) missing.add(SecurityConstants.HEADER_E2E_NONCE);
        if (!missing.isEmpty()) {
            // Header NAMES only, never values: safe to log
            throw E2EException.required("missing headers " + missing + " on " + request.getMethod() + " " + request.getRequestURI()
                    + " (user-agent: " + RequestUtil.clientContext(request).userAgent() + ")");
        }
        if (!cryptoService.currentKeyId().equals(keyId)) {
            throw E2EException.keyMismatch();
        }
        if (wrappedKey.length() > MAX_WRAPPED_KEY_LENGTH || !NONCE.matcher(nonce).matches()) {
            throw E2EException.invalid("header format");
        }
        verifyFreshness(rawTimestamp);

        SecretKey key = cryptoService.unwrapSessionKey(wrappedKey);

        if (!nonceStore.registerIfAbsent(nonce, properties.replayWindow().multipliedBy(2))) {
            throw E2EException.invalid("nonce replay");
        }

        String method = request.getMethod();
        String path = request.getRequestURI();
        byte[] requestAad = String.join("|", method, path, rawTimestamp, nonce).getBytes(StandardCharsets.UTF_8);
        byte[] responseAad = String.join("|", "RESP", method, path, nonce).getBytes(StandardCharsets.UTF_8);
        return new E2EContext(key, requestAad, responseAad);
    }

    private void verifyFreshness(String rawTimestamp) {
        long epochMillis;
        try {
            epochMillis = Long.parseLong(rawTimestamp);
        } catch (NumberFormatException ex) {
            throw E2EException.invalid("timestamp not numeric");
        }
        Duration skew = Duration.between(Instant.ofEpochMilli(epochMillis), clock.instant()).abs();
        if (skew.compareTo(properties.replayWindow()) > 0) {
            throw E2EException.invalid("timestamp outside replay window");
        }
    }
}