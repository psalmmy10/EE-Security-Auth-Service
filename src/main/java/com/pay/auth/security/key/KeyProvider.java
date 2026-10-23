package com.pay.auth.security.key;

import java.security.KeyPair;

import com.pay.auth.constant.enums.KeyPurpose;

/**
 * Strategy for sourcing key material. Production: PKCS#12 keystore (or an HSM/KMS-backed
 * implementation). Development: ephemeral in-memory keys. Callers never know which.
 */
public interface KeyProvider {

    KeyPair keyPair(KeyPurpose purpose);
}
