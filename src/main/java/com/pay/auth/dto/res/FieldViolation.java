package com.pay.auth.dto.res;

/** Field name + constraint message only. Rejected values are never echoed back. */
public record FieldViolation(String field, String message) {
}
