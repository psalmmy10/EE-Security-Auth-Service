package com.pay.auth.service.impl;

import com.pay.auth.config.properties.E2EProperties;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.dto.common.EncryptedEnvelope;
import com.pay.auth.dto.req.E2EDecryptToolRequest;
import com.pay.auth.dto.req.E2EEncryptToolRequest;
import com.pay.auth.dto.req.E2EProxyRequest;
import com.pay.auth.dto.res.E2EEncryptToolResponse;
import com.pay.auth.dto.res.E2EProxyResponse;
import com.pay.auth.dto.res.PublicKeyResponse;
import com.pay.auth.exception.CryptoException;
import com.pay.auth.service.CryptoService;
import com.pay.auth.service.E2ETestToolService;
import com.pay.auth.util.CryptoUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DEV TOOL ONLY — exists only under the "dev" profile.
 * Performs exactly what a real client does (see tools/E2EClient.java), using only the PUBLIC key
 * for encryption and the caller-supplied session key for decryption. It never uses the server's
 * private key, so it is not a decryption oracle for captured traffic.
 */
@Service
@Profile("dev")
@RequiredArgsConstructor
public class E2ETestToolServiceImpl implements E2ETestToolService {

    private final CryptoService cryptoService;
    private final E2EProperties e2eProperties;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final Environment environment;

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Override
    public E2EEncryptToolResponse encrypt(E2EEncryptToolRequest request) {
        PublicKeyResponse keyInfo = cryptoService.publicKey();
        String method = request.method();
        String path = request.path().split("\\?", 2)[0];   // AAD uses the path without the query string

        SecretKey aesKey = CryptoUtil.generateAesKey();
        String wrappedKey = CryptoUtil.base64(CryptoUtil.rsaOaepEncrypt(publicKey(keyInfo.publicKey()), aesKey.getEncoded()));
        Instant now = clock.instant();
        String timestamp = Long.toString(now.toEpochMilli());
        String nonce = CryptoUtil.base64(CryptoUtil.randomBytes(16));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(SecurityConstants.HEADER_E2E_KEY, wrappedKey);
        headers.put(SecurityConstants.HEADER_E2E_KEY_ID, keyInfo.keyId());
        headers.put(SecurityConstants.HEADER_E2E_TIMESTAMP, timestamp);
        headers.put(SecurityConstants.HEADER_E2E_NONCE, nonce);

        EncryptedEnvelope body = null;
        if (request.payload() != null && !request.payload().isNull()) {
            byte[] aad = String.join("|", method, path, timestamp, nonce).getBytes(StandardCharsets.UTF_8);
            body = cryptoService.encrypt(aesKey, toJsonBytes(request.payload()), aad);
        }

        return new E2EEncryptToolResponse(
                headers,
                body,
                CryptoUtil.base64(aesKey.getEncoded()),
                String.join("|", "RESP", method, path, nonce),
                now.plus(e2eProperties.replayWindow()));
    }

    @Override
    public JsonNode decrypt(E2EDecryptToolRequest request) {
        SecretKey key = CryptoUtil.toAesKey(CryptoUtil.fromBase64(request.sessionKey()));
        byte[] plaintext = cryptoService.decrypt(key, request.response(),
                request.responseAad().getBytes(StandardCharsets.UTF_8));
        try {
            return objectMapper.readTree(plaintext);
        } catch (java.io.IOException ex) {
            throw new CryptoException("decrypted response is not JSON", ex);
        }
    }

    @Override
    public E2EProxyResponse proxy(E2EProxyRequest request) {
        E2EEncryptToolResponse encrypted = encrypt(new E2EEncryptToolRequest(request.method(), request.path(), request.payload()));

        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(localBaseUrl() + request.path()))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("User-Agent", "dev-e2e-proxy");
        encrypted.headers().forEach(builder::header);
        if (StringUtils.hasText(request.accessToken())) {
            builder.header("Authorization", "Bearer " + request.accessToken().trim());
        }
        builder.method(request.method(), encrypted.body() == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(toJsonBytes(objectMapper.valueToTree(encrypted.body()))));

        HttpResponse<String> response;
        try {
            response = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new IllegalStateException("Proxy could not reach the local endpoint " + request.path(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Proxy call interrupted", ex);
        }

        JsonNode received = readJson(response.body());
        boolean responseEncrypted = "true".equals(
                response.headers().firstValue(SecurityConstants.HEADER_E2E_ENCRYPTED).orElse(null));
        JsonNode decrypted = responseEncrypted
                ? decrypt(new E2EDecryptToolRequest(encrypted.sessionKey(), encrypted.responseAad(),
                        new EncryptedEnvelope(received.path("iv").asText(), received.path("data").asText())))
                : received;

        return new E2EProxyResponse(response.statusCode(), responseEncrypted, encrypted.headers(),
                encrypted.body(), received, decrypted);
    }

    private String localBaseUrl() {
        String port = environment.getProperty("local.server.port", environment.getProperty("server.port", "8080"));
        return "http://127.0.0.1:" + port;
    }

    private JsonNode readJson(String body) {
        try {
            return objectMapper.readTree(body == null || body.isBlank() ? "{}" : body);
        } catch (IOException ex) {
            return objectMapper.getNodeFactory().textNode(body);
        }
    }

    private byte[] toJsonBytes(JsonNode payload) {
        try {
            return objectMapper.writeValueAsBytes(payload);
        } catch (JsonProcessingException ex) {
            throw new CryptoException("payload is not serialisable", ex);
        }
    }

    private static PublicKey publicKey(String base64Spki) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CryptoUtil.fromBase64(base64Spki)));
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("server public key could not be parsed", ex);
        }
    }
}