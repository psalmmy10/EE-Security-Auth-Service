package com.pay.auth.security.key;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.pay.auth.constant.enums.KeyPurpose;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/** DEV ONLY. Keys die with the process, so every restart invalidates all tokens. */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "app.security.keys", name = "source", havingValue = "ephemeral")
public class EphemeralKeyProvider implements KeyProvider {

    private final Map<KeyPurpose, KeyPair> keyPairs;

    public EphemeralKeyProvider() {
        log.warn("Using EPHEMERAL RSA keys — development only. Never enable outside local environments.");
        EnumMap<KeyPurpose, KeyPair> generated = new EnumMap<>(KeyPurpose.class);
        for (KeyPurpose purpose : KeyPurpose.values()) {
            generated.put(purpose, generate());
        }
        this.keyPairs = Collections.unmodifiableMap(generated);
    }

    @Override
    public KeyPair keyPair(KeyPurpose purpose) {
        return keyPairs.get(purpose);
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA unavailable", ex);
        }
    }
}
