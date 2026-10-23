package com.pay.auth.security.e2e;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.pay.auth.config.properties.E2EProperties;

/**
 * Runs after authentication and before argument resolution, so the key is available to the
 * body advice. Covers body-less calls (GET /me, POST /logout) whose responses still need encrypting.
 */
@Component
@RequiredArgsConstructor
public class E2EEnforcementInterceptor implements HandlerInterceptor {

    private final E2ESessionKeyResolver keyResolver;
    private final E2EProperties properties;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (properties.enabled()
                && handler instanceof HandlerMethod handlerMethod
                && E2EContextHolder.isEncryptionRequired(handlerMethod.getBeanType(), handlerMethod.getMethod())) {
            request.setAttribute(E2EContext.REQUEST_ATTRIBUTE, keyResolver.resolve(request));
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        request.removeAttribute(E2EContext.REQUEST_ATTRIBUTE);
    }
}