package com.pay.auth.security.key;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.pay.auth.config.properties.KeyProperties;
import com.pay.auth.constant.enums.KeyPurpose;
import com.pay.auth.exception.StartupConfigurationException;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/** Default (fail-closed) provider: the service refuses to start without real key material. */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "app.security.keys", name = "source", havingValue = "keystore", matchIfMissing = true)
public class KeystoreKeyProvider implements KeyProvider {

    private static final int MIN_RSA_BITS = 3072;

    private final Map<KeyPurpose, KeyPair> keyPairs;

    public KeystoreKeyProvider(KeyProperties properties, ResourceLoader resourceLoader) {
        KeyProperties.Keystore cfg = properties.keystore();
        if (cfg == null || !StringUtils.hasText(cfg.location()) || !StringUtils.hasText(cfg.password())) {
            throw new StartupConfigurationException("Keystore location or password is not configured.",
                    "Set KEYSTORE_LOCATION (e.g. file:./secrets/auth-keys.p12) and KEYSTORE_PASSWORD, "
                            + "or use app.security.keys.source=ephemeral in dev.");
        }
        if (cfg.jwtSigningAlias().equals(cfg.payloadEncryptionAlias())) {
            throw new StartupConfigurationException("JWT signing and payload encryption are configured with the same keystore alias.",
                    "Use two different aliases (jwt-signing and payload-encryption).");
        }
        char[] password = cfg.password().toCharArray();
        try (InputStream in = resourceLoader.getResource(cfg.location()).getInputStream()) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, password);
            EnumMap<KeyPurpose, KeyPair> loaded = new EnumMap<>(KeyPurpose.class);
            loaded.put(KeyPurpose.JWT_SIGNING, load(keyStore, cfg.jwtSigningAlias(), password));
            loaded.put(KeyPurpose.PAYLOAD_ENCRYPTION, load(keyStore, cfg.payloadEncryptionAlias(), password));
            this.keyPairs = Collections.unmodifiableMap(loaded);
            log.info("Loaded JWT signing and payload encryption keys from keystore");
        } catch (IOException | GeneralSecurityException ex) {
            throw new StartupConfigurationException("Unable to load keys from keystore '" + cfg.location() + "': " + ex.getMessage(),
                    "Check that the file exists at KEYSTORE_LOCATION, that KEYSTORE_PASSWORD is correct, "
                            + "and that it contains the aliases jwt-signing and payload-encryption "
                            + "(keytool -list -keystore <file> -storepass <password>).", ex);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Override
    public KeyPair keyPair(KeyPurpose purpose) {
        return keyPairs.get(purpose);
    }

    private static KeyPair load(KeyStore keyStore, String alias, char[] password) throws GeneralSecurityException {
        Key key = keyStore.getKey(alias, password);
        if (!(key instanceof RSAPrivateKey privateKey)) {
            throw new StartupConfigurationException("Keystore alias '" + alias + "' is missing or is not an RSA private key.",
                    "Generate it with scripts/generate-keys.sh or keytool -genkeypair -alias " + alias + " -keyalg RSA -keysize 3072.");
        }
        Certificate certificate = keyStore.getCertificate(alias);
        if (certificate == null || !(certificate.getPublicKey() instanceof RSAPublicKey publicKey)) {
            throw new StartupConfigurationException("Keystore alias '" + alias + "' has no RSA certificate.",
                    "Regenerate the key pair for alias '" + alias + "' with keytool -genkeypair.");
        }
        if (publicKey.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new StartupConfigurationException("Keystore alias '" + alias + "' is smaller than " + MIN_RSA_BITS + " bits.",
                    "Regenerate it with -keysize " + MIN_RSA_BITS + ".");
        }
        return new KeyPair(publicKey, privateKey);
    }
}