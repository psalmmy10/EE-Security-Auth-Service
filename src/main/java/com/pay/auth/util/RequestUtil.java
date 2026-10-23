package com.pay.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import com.pay.auth.model.ClientContext;

/**
 * Remote address relies on server.forward-headers-strategy=framework, so X-Forwarded-For is
 * honoured only through Spring's trusted-proxy handling, never parsed naively here.
 */
public final class RequestUtil {

    private static final int MAX_IP_LENGTH = 45;
    private static final int MAX_USER_AGENT_LENGTH = 255;

    private RequestUtil() {
    }

    public static ClientContext clientContext(HttpServletRequest request) {
        return new ClientContext(
                truncate(request.getRemoteAddr(), MAX_IP_LENGTH),
                truncate(sanitize(request.getHeader(HttpHeaders.USER_AGENT)), MAX_USER_AGENT_LENGTH));
    }

    /** Strips control characters to prevent log/CRLF injection via headers. */
    private static String sanitize(String value) {
        return value == null ? null : value.replaceAll("\\p{Cntrl}", "");
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
