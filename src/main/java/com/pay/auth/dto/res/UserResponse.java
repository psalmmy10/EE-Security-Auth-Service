package com.pay.auth.dto.res;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.pay.auth.constant.enums.UserStatus;

public record UserResponse(
        UUID id,
        String email,
        String firstName,
        String lastName,
        UserStatus status,
        List<String> roles,
        Instant createdAt,
        Instant lastLoginAt) {
}
