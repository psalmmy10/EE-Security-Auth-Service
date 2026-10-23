package com.pay.auth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pay.auth.constant.SecurityConstants;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Runs before Spring Security so even 401/403 responses carry a correlation id.
 * Inbound ids are accepted only if they match a strict pattern (prevents log injection).
 * MDC is thread-local; with one virtual thread per request this is safe and always cleared.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9\\-]{8,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String inbound = request.getHeader(SecurityConstants.HEADER_CORRELATION_ID);
        String correlationId = inbound != null && SAFE_ID.matcher(inbound).matches()
                ? inbound
                : UUID.randomUUID().toString();
        MDC.put(SecurityConstants.MDC_CORRELATION_ID, correlationId);
        response.setHeader(SecurityConstants.HEADER_CORRELATION_ID, correlationId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(SecurityConstants.MDC_CORRELATION_ID);
        }
    }
}
