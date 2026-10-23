package com.banffpay.auth.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.pay.auth.exception.CryptoException;
import com.pay.auth.util.CryptoUtil;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoUtilTest {

    private static KeyPair serverKeys;
    private static final byte[] AAD = "POST|/api/v1/auth/login|1730000000000|bm9uY2Utbm9uY2Utbm9uY2U=".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        serverKeys = generator.generateKeyPair();
    }

    @Test
    void hybridRoundTripRestoresPlaintext() {
        SecretKey clientKey = CryptoUtil.generateAesKey();
        byte[] wrapped = CryptoUtil.rsaOaepEncrypt(serverKeys.getPublic(), clientKey.getEncoded());
        SecretKey serverSide = CryptoUtil.toAesKey(CryptoUtil.rsaOaepDecrypt(serverKeys.getPrivate(), wrapped));

        byte[] iv = CryptoUtil.randomBytes(CryptoUtil.GCM_IV_BYTES);
        byte[] plaintext = "{\"email\":\"user@banffpay.com\"}".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = CryptoUtil.aesGcmEncrypt(clientKey, iv, plaintext, AAD);

        assertThat(CryptoUtil.aesGcmDecrypt(serverSide, iv, ciphertext, AAD)).isEqualTo(plaintext);
    }

    @Test
    void ciphertextReplayedAgainstAnotherEndpointIsRejected() {
        SecretKey key = CryptoUtil.generateAesKey();
        byte[] iv = CryptoUtil.randomBytes(CryptoUtil.GCM_IV_BYTES);
        byte[] ciphertext = CryptoUtil.aesGcmEncrypt(key, iv, "{}".getBytes(StandardCharsets.UTF_8), AAD);
        byte[] otherEndpoint = "POST|/api/v1/admin/users|1730000000000|bm9uY2Utbm9uY2Utbm9uY2U=".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> CryptoUtil.aesGcmDecrypt(key, iv, ciphertext, otherEndpoint))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void tamperedCiphertextIsRejected() {
        SecretKey key = CryptoUtil.generateAesKey();
        byte[] iv = CryptoUtil.randomBytes(CryptoUtil.GCM_IV_BYTES);
        byte[] ciphertext = CryptoUtil.aesGcmEncrypt(key, iv, "{\"amount\":100}".getBytes(StandardCharsets.UTF_8), AAD);
        ciphertext[0] ^= 0x01;

        assertThatThrownBy(() -> CryptoUtil.aesGcmDecrypt(key, iv, ciphertext, AAD)).isInstanceOf(CryptoException.class);
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThatThrownBy(() -> CryptoUtil.toAesKey(new byte[16])).isInstanceOf(CryptoException.class);
    }
}
