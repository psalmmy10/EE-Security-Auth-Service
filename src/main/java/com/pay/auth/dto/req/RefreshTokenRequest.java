package com.pay.auth.dto.req;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @NotBlank(message = "Refresh token is required")
        @Size(max = 256)
        String refreshToken) {

    @Override
    public String toString() {
        return "RefreshTokenRequest[refreshToken=****]";
    }
}
