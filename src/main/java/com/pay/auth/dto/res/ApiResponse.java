package com.pay.auth.dto.res;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.constant.enums.ErrorCode;

import org.slf4j.MDC;

import java.time.Instant;
import java.util.List;

/** Uniform envelope for every response; the correlation id lets support trace without leaking internals. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        boolean success,
        String code,
        String message,
        T data,
        List<FieldViolation> errors,
        String correlationId,
        Instant timestamp) {

    private static final String SUCCESS_CODE = "SUCCESS";

    public static <T> ApiResponse<T> success(T data, String message) {
        return new ApiResponse<>(true, SUCCESS_CODE, message, data, null, currentCorrelationId(), Instant.now());
    }

    public static ApiResponse<Void> failure(ErrorCode errorCode) {
        return failure(errorCode, null);
    }

    public static ApiResponse<Void> failure(ErrorCode errorCode, List<FieldViolation> errors) {
        return new ApiResponse<>(false, errorCode.getCode(), errorCode.getMessage(), null,
                errors == null || errors.isEmpty() ? null : List.copyOf(errors), currentCorrelationId(), Instant.now());
    }

    private static String currentCorrelationId() {
        return MDC.get(SecurityConstants.MDC_CORRELATION_ID);
    }
}
