package com.pay.auth.security.ratelimit;

import com.pay.auth.config.properties.RateLimitProperties;
import com.pay.auth.constant.ApiPaths;
import com.pay.auth.constant.enums.ErrorCode;
import com.pay.auth.security.handler.SecurityErrorWriter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Per-IP throttling of login, signup and refresh. Runs BEFORE Spring Security and before any
 * RSA or BCrypt work, so a flood is rejected cheaply. Complements (doesn't replace) per-account
 * lockout and gateway/WAF limits. The client IP comes from request.getRemoteAddr(), which the
 * framework-level forwarded-header handling sets from the trusted proxy's X-Forwarded-For.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimiter rateLimiter;
    private final RateLimitProperties properties;
    private final SecurityErrorWriter errorWriter;
    private final MeterRegistry meterRegistry;

    private Map<String, RateLimitProperties.Rule> rules() {
        return Map.of(
                ApiPaths.AUTH + "/login", properties.login(),
                ApiPaths.AUTH + "/signup", properties.signup(),
                ApiPaths.AUTH + "/refresh", properties.refresh());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.enabled() || !"POST".equals(request.getMethod()) || !rules().containsKey(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String endpoint = path.substring(path.lastIndexOf('/') + 1);
        RateLimitProperties.Rule rule = rules().get(path);

        RateLimitDecision decision = rateLimiter.tryAcquire(endpoint + ":" + request.getRemoteAddr(), rule.limit(), rule.window());
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        meterRegistry.counter("auth.rate_limited", "endpoint", endpoint).increment();
        log.warn("Rate limit hit on {} from {}", endpoint, request.getRemoteAddr());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(decision.retryAfterSeconds()));
        errorWriter.write(response, ErrorCode.TOO_MANY_REQUESTS);
    }
}

