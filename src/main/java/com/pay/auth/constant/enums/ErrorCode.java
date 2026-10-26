package com.pay.auth.constant.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Every client-facing error. Messages are deliberately generic: internal details go to
 * logs (tagged with the correlation id), never to the response.
 */
@Getter
public enum ErrorCode {

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "AUTH-4000", "Request validation failed"),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST, "AUTH-4001", "Malformed request"),
    E2E_REQUIRED(HttpStatus.BAD_REQUEST, "AUTH-4002", "This endpoint requires an encrypted payload"),
    E2E_INVALID(HttpStatus.BAD_REQUEST, "AUTH-4003", "Unable to process secure payload"),
    E2E_KEY_MISMATCH(HttpStatus.BAD_REQUEST, "AUTH-4004", "Encryption key is outdated; fetch the current public key"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "AUTH-4010", "Invalid email or password"),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "AUTH-4011", "Invalid or expired token"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "AUTH-4012", "Authentication is required"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "AUTH-4030", "You do not have permission to perform this action"),
    ACCOUNT_INACTIVE(HttpStatus.FORBIDDEN, "AUTH-4031", "Account is not active. Please contact support"),
    OPERATION_NOT_ALLOWED(HttpStatus.FORBIDDEN, "AUTH-4032", "Operation not allowed"),
    HTTPS_REQUIRED(HttpStatus.FORBIDDEN, "AUTH-4033", "HTTPS is required"),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "AUTH-4040", "Resource not found"),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "AUTH-4050", "Method not allowed"),
    REGISTRATION_CONFLICT(HttpStatus.CONFLICT, "AUTH-4090", "Unable to complete registration with the supplied details"),
    ACCOUNT_LOCKED(HttpStatus.LOCKED, "AUTH-4230", "Account temporarily locked. Please try again later"),
    TOO_MANY_REQUESTS(HttpStatus.TOO_MANY_REQUESTS, "AUTH-4290", "Too many requests. Please slow down and try again later"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-5000", "An unexpected error occurred"),
    SERVICE_BUSY(HttpStatus.SERVICE_UNAVAILABLE, "AUTH-5030", "Service is busy. Please retry shortly");

    private final HttpStatus status;
    private final String code;
    private final String message;

    ErrorCode(HttpStatus status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
