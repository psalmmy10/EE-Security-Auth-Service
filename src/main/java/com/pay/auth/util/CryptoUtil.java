package com.pay.auth.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import com.pay.auth.exception.CryptoException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

/**
 * Stateless crypto primitives.
 * <ul>
 *   <li>RSA-OAEP with SHA-256 for both digest and MGF1 — byte-compatible with WebCrypto
 *       {@code {name:"RSA-OAEP", hash:"SHA-256"}} and JOSE "RSA-OAEP-256".</li>
 *   <li>AES-256-GCM, 96-bit IV, 128-bit tag, with AAD.</li>
 * </ul>
 * {@link Cipher} is not thread-safe, so a new instance is created per call (cheap).
 * SecureRandom is thread-safe and shared.
 */
public final class CryptoUtil {

    public static final int AES_KEY_BYTES = 32;
    public static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String RSA_OAEP = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec OAEP_SHA256 =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder B64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();
    private static final Base64.Encoder B64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private CryptoUtil() {
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static String randomUrlSafeToken(int byteLength) {
        return B64_URL_ENCODER.encodeToString(randomBytes(byteLength));
    }

    public static SecretKey generateAesKey() {
        return new SecretKeySpec(randomBytes(AES_KEY_BYTES), "AES");
    }

    public static SecretKey toAesKey(byte[] raw) {
        if (raw == null || raw.length != AES_KEY_BYTES) {
            throw new CryptoException("AES key must be exactly " + AES_KEY_BYTES + " bytes");
        }
        return new SecretKeySpec(raw, "AES");
    }

    public static byte[] aesGcmEncrypt(SecretKey key, byte[] iv, byte[] plaintext, byte[] aad) {
        return aesGcm(Cipher.ENCRYPT_MODE, key, iv, plaintext, aad);
    }

    public static byte[] aesGcmDecrypt(SecretKey key, byte[] iv, byte[] ciphertext, byte[] aad) {
        return aesGcm(Cipher.DECRYPT_MODE, key, iv, ciphertext, aad);
    }

    public static byte[] rsaOaepEncrypt(PublicKey publicKey, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_OAEP);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("RSA-OAEP encryption failed", ex);
        }
    }

    public static byte[] rsaOaepDecrypt(PrivateKey privateKey, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_OAEP);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("RSA-OAEP decryption failed", ex);
        }
    }

    public static String base64(byte[] bytes) {
        return B64_ENCODER.encodeToString(bytes);
    }

    public static byte[] fromBase64(String value) {
        try {
            return B64_DECODER.decode(value);
        } catch (IllegalArgumentException ex) {
            throw new CryptoException("invalid base64 input", ex);
        }
    }

    private static byte[] aesGcm(int mode, SecretKey key, byte[] iv, byte[] input, byte[] aad) {
        if (iv == null || iv.length != GCM_IV_BYTES) {
            throw new CryptoException("GCM IV must be " + GCM_IV_BYTES + " bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(mode, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("AES-GCM operation failed", ex);
        }
    }
}
