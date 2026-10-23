package com.pay.auth.service.impl;

import org.springframework.stereotype.Service;

import com.pay.auth.constant.enums.KeyPurpose;
import com.pay.auth.dto.common.EncryptedEnvelope;
import com.pay.auth.dto.res.PublicKeyResponse;
import com.pay.auth.security.key.KeyProvider;
import com.pay.auth.service.CryptoService;
import com.pay.auth.util.CryptoUtil;
import com.pay.auth.util.HashUtil;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Arrays;

@Service
public class HybridCryptoServiceImpl implements CryptoService {

    private static final String KEY_ALGORITHM = "RSA-OAEP-256";
    private static final String CONTENT_ENCRYPTION = "A256GCM";

    private final PrivateKey privateKey;
    private final PublicKeyResponse publicKeyResponse;

    public HybridCryptoServiceImpl(KeyProvider keyProvider) {
        var keyPair = keyProvider.keyPair(KeyPurpose.PAYLOAD_ENCRYPTION);
        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
        this.privateKey = keyPair.getPrivate();
        this.publicKeyResponse = new PublicKeyResponse(
                HashUtil.sha256Hex(encodedPublicKey).substring(0, 16),
                KEY_ALGORITHM,
                CONTENT_ENCRYPTION,
                CryptoUtil.base64(encodedPublicKey));
    }

    @Override
    public PublicKeyResponse publicKey() {
        return publicKeyResponse;
    }

    @Override
    public String currentKeyId() {
        return publicKeyResponse.keyId();
    }

    @Override
    public SecretKey unwrapSessionKey(String base64WrappedKey) {
        byte[] raw = CryptoUtil.rsaOaepDecrypt(privateKey, CryptoUtil.fromBase64(base64WrappedKey));
        try {
            return CryptoUtil.toAesKey(raw.clone());
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, EncryptedEnvelope envelope, byte[] aad) {
        return CryptoUtil.aesGcmDecrypt(key, CryptoUtil.fromBase64(envelope.iv()), CryptoUtil.fromBase64(envelope.data()), aad);
    }

    @Override
    public EncryptedEnvelope encrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        byte[] iv = CryptoUtil.randomBytes(CryptoUtil.GCM_IV_BYTES);
        byte[] ciphertext = CryptoUtil.aesGcmEncrypt(key, iv, plaintext, aad);
        return new EncryptedEnvelope(CryptoUtil.base64(iv), CryptoUtil.base64(ciphertext));
    }
}
