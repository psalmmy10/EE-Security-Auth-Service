package com.pay.auth.security.filter;

import com.pay.auth.constant.enums.ErrorCode;
import com.pay.auth.security.handler.SecurityErrorWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rejects any request that did not arrive over HTTPS (app.security.require-https=true in staging/prod).
 * Behind a load balancer, TLS ends at the proxy; with server.forward-headers-strategy=framework,
 * Spring's ForwardedHeaderFilter (which runs first) turns X-Forwarded-Proto into request.isSecure().
 * Health checks are exempt so an internal load-balancer probe over plain HTTP still works.
 * HSTS (set by SecurityConfig) then tells browsers never to try plain HTTP again.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class HttpsEnforcementFilter extends OncePerRequestFilter {

    private final boolean requireHttps;
    private final SecurityErrorWriter errorWriter;

    public HttpsEnforcementFilter(@Value("${app.security.require-https:false}") boolean requireHttps,
                                  SecurityErrorWriter errorWriter) {
        this.requireHttps = requireHttps;
        this.errorWriter = errorWriter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !requireHttps || request.isSecure() || request.getRequestURI().startsWith("/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        log.warn("Rejected non-HTTPS request to {} from {}", request.getRequestURI(), request.getRemoteAddr());
        errorWriter.write(response, ErrorCode.HTTPS_REQUIRED);
    }
}
