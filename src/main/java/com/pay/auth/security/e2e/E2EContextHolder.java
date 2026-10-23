package com.pay.auth.security.e2e;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.lang.reflect.Method;
import java.util.Optional;

public final class E2EContextHolder {

    private E2EContextHolder() {
    }

    public static Optional<E2EContext> current() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return Optional.empty();
        }
        Object value = attributes.getAttribute(E2EContext.REQUEST_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        return value instanceof E2EContext context ? Optional.of(context) : Optional.empty();
    }

    public static boolean isEncryptionRequired(Class<?> handlerType, Method handlerMethod) {
        return (handlerMethod != null && AnnotatedElementUtils.hasAnnotation(handlerMethod, E2EEncrypted.class))
                || AnnotatedElementUtils.hasAnnotation(handlerType, E2EEncrypted.class);
    }
}
