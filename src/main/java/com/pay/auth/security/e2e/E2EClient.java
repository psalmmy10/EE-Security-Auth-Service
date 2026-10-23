package com.pay.auth.security.e2e;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Standalone E2E test client — JDK 21 only, no dependencies, no build needed.
 *
 *   java tools/E2EClient.java                                   (defaults)
 *   java tools/E2EClient.java http://localhost:8080 kayode@test.com "Str0ng#Password1"
 *
 * Runs: fetch public key -> encrypted SIGNUP -> encrypted LOGIN -> encrypted GET /me,
 * printing what actually travels over the wire and the decrypted response.
 */
public class E2EClient {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final OAEPParameterSpec OAEP_SHA256 =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private static String baseUrl;
    private static String keyId;
    private static PublicKey serverKey;

    public static void main(String[] args) throws Exception {
        baseUrl = args.length > 0 ? args[0] : "http://localhost:8080";
        String email = args.length > 1 ? args[1] : "user" + System.currentTimeMillis() + "@test.com";
        String password = args.length > 2 ? args[2] : "Str0ng#Password1";

        fetchPublicKey();

        String signupJson = """
                {"email":"%s","password":"%s","firstName":"Kayode","lastName":"Ajayi"}"""
                .formatted(email, password);
        call("POST", "/api/v1/auth/signup", signupJson, null);

        String loginJson = """
                {"email":"%s","password":"%s"}""".formatted(email, password);
        String loginResponse = call("POST", "/api/v1/auth/login", loginJson, null);

        String accessToken = field(loginResponse, "accessToken");
        if (accessToken != null) {
            call("GET", "/api/v1/users/me", null, accessToken);
        }
    }

    private static void fetchPublicKey() throws Exception {
        HttpResponse<String> res = HTTP.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/crypto/public-key")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        keyId = field(res.body(), "keyId");
        byte[] spki = Base64.getDecoder().decode(field(res.body(), "publicKey"));
        serverKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
        System.out.println("== Server public key fetched, keyId=" + keyId + "\n");
    }

    /** Sends one encrypted request and returns the decrypted response body. */
    private static String call(String method, String path, String jsonBody, String bearer) throws Exception {
        // 1. Fresh AES-256 key for this request, wrapped with the server's RSA key
        byte[] rawKey = random(32);
        SecretKey aesKey = new SecretKeySpec(rawKey, "AES");
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, serverKey, OAEP_SHA256);
        String wrappedKey = b64(rsa.doFinal(rawKey));

        String timestamp = Long.toString(System.currentTimeMillis());
        String nonce = b64(random(16));

        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .header("X-E2E-Key", wrappedKey)
                .header("X-E2E-Key-Id", keyId)
                .header("X-E2E-Timestamp", timestamp)
                .header("X-E2E-Nonce", nonce);
        if (bearer != null) {
            req.header("Authorization", "Bearer " + bearer);
        }

        // 2. Encrypt body, bound to METHOD|PATH|TIMESTAMP|NONCE
        if (jsonBody != null) {
            byte[] iv = random(12);
            byte[] aad = (method + "|" + path + "|" + timestamp + "|" + nonce).getBytes(StandardCharsets.UTF_8);
            String envelope = "{\"iv\":\"" + b64(iv) + "\",\"data\":\""
                    + b64(gcm(Cipher.ENCRYPT_MODE, aesKey, iv, jsonBody.getBytes(StandardCharsets.UTF_8), aad)) + "\"}";
            System.out.println("== " + method + " " + path);
            System.out.println("   plaintext : " + jsonBody.replaceAll("\"password\":\"[^\"]*\"", "\"password\":\"****\""));
            System.out.println("   on the wire: " + envelope);
            req.method(method, HttpRequest.BodyPublishers.ofString(envelope));
        } else {
            System.out.println("== " + method + " " + path + " (no body)");
            req.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> res = HTTP.send(req.build(), HttpResponse.BodyHandlers.ofString());
        String body = res.body();

        // 3. Decrypt response, bound to RESP|METHOD|PATH|NONCE
        if ("true".equals(res.headers().firstValue("X-E2E-Encrypted").orElse(null))) {
            byte[] aad = ("RESP|" + method + "|" + path + "|" + nonce).getBytes(StandardCharsets.UTF_8);
            body = new String(gcm(Cipher.DECRYPT_MODE, aesKey,
                    Base64.getDecoder().decode(field(body, "iv")),
                    Base64.getDecoder().decode(field(body, "data")), aad), StandardCharsets.UTF_8);
            System.out.println("   HTTP " + res.statusCode() + " (encrypted) -> decrypted: " + body + "\n");
        } else {
            System.out.println("   HTTP " + res.statusCode() + " (plain): " + body + "\n");
        }
        return body;
    }

    private static byte[] gcm(int mode, SecretKey key, byte[] iv, byte[] input, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
