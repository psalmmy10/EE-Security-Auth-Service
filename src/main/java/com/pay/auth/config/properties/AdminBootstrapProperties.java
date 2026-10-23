package com.pay.auth.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.bootstrap.admin")
public record AdminBootstrapProperties(boolean enabled, String email, String password, String firstName, String lastName) {

    @Override
    public String toString() {
        return "AdminBootstrapProperties[enabled=" + enabled + ", email=" + email + ", password=****]";
    }
}
