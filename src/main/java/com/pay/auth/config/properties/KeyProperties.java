package com.pay.auth.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.security.keys")
public record KeyProperties(@NotBlank String source, Keystore keystore) {

    public record Keystore(String location, String password, String jwtSigningAlias, String payloadEncryptionAlias) {
        @Override
        public String toString() {
            return "Keystore[location=" + location + ", password=****, jwtSigningAlias=" + jwtSigningAlias
                    + ", payloadEncryptionAlias=" + payloadEncryptionAlias + "]";
        }
    }
}
