package com.pay.auth.dto.req;

import com.pay.auth.constant.enums.UserStatus;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdateUserStatusRequest(
        @NotNull(message = "Status is required") UserStatus status,
        @Size(max = 250, message = "Reason must not exceed 250 characters") String reason) {
}
