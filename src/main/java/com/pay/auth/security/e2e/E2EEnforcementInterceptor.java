package com.pay.auth.security.e2e;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.beans.factory.annotation.Value;

import com.pay.auth.config.properties.E2EProperties;
import com.pay.auth.constant.SecurityConstants;

/**
 * Runs after authentication and before argument resolution, so the key is available to the
 * body advice. Covers body-less calls (GET /me, POST /logout) whose responses still need encrypting.
 */
@Component
@RequiredArgsConstructor
public class E2EEnforcementInterceptor implements HandlerInterceptor {

    
@Value("${app.security.e2e.swagger-test-enabled:false}")
private boolean swaggerTestEnabled;

    private final E2ESessionKeyResolver keyResolver;
    private final E2EProperties properties;

    

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        
        if (properties.enabled()
                && handler instanceof HandlerMethod handlerMethod
                && E2EContextHolder.isEncryptionRequired(handlerMethod.getBeanType(), handlerMethod.getMethod())) {
            request.setAttribute(E2EContext.REQUEST_ATTRIBUTE, keyResolver.resolve(request));


        }


        if (swaggerTestEnabled) {
            response.setHeader(
                    "X-E2E-Request-Nonce",
                    request.getHeader(SecurityConstants.HEADER_E2E_NONCE)
            );
        }

        // response.setHeader(
        //         "X-E2E-Request-Nonce",
        //         request.getHeader("X-E2E-Nonce")
        // );

        return true;
    }

    

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        request.removeAttribute(E2EContext.REQUEST_ATTRIBUTE);
    }
}