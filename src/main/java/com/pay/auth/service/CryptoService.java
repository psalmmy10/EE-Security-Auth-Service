package com.pay.auth.service;

import javax.crypto.SecretKey;

import com.pay.auth.dto.common.EncryptedEnvelope;
import com.pay.auth.dto.res.PublicKeyResponse;

/** Hybrid payload encryption (RSA-OAEP-256 key transport + AES-256-GCM content). */
public interface CryptoService {

    PublicKeyResponse publicKey();

    String currentKeyId();

    SecretKey unwrapSessionKey(String base64WrappedKey);

    byte[] decrypt(SecretKey key, EncryptedEnvelope envelope, byte[] aad);

    EncryptedEnvelope encrypt(SecretKey key, byte[] plaintext, byte[] aad);
}
