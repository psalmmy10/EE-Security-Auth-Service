package com.pay.auth.security.e2e;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller (or a single handler) as end-to-end encrypted: requests MUST carry the
 * E2E headers, bodies are decrypted before binding/validation, and responses are encrypted
 * with the same per-request key. Controllers stay unaware of crypto (separation of concerns).
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface E2EEncrypted {
}
