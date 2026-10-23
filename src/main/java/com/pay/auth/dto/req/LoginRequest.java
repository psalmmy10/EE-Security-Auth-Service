package com.pay.auth.dto.req;

import com.pay.auth.util.MaskingUtil;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be a valid address")
        @Size(max = 150)
        String email,

        @NotBlank(message = "Password is required")
        @Size(max = 64)
        String password) {

    @Override
    public String toString() {
        return "LoginRequest[email=" + MaskingUtil.maskEmail(email) + ", password=****]";
    }
}
