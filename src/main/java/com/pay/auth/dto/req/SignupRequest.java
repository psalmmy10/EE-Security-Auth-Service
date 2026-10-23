package com.pay.auth.dto.req;

import com.pay.auth.util.MaskingUtil;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Deliberately has no role field: public signup can only ever produce ROLE_USER, and
 * unknown JSON properties are rejected (fail-on-unknown-properties) to block mass assignment.
 */
public record SignupRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be a valid address")
        @Size(max = 150, message = "Email must not exceed 150 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 12, max = 64, message = "Password must be between 12 and 64 characters")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
                message = "Password must contain upper-case, lower-case, digit and special characters")
        String password,

        @NotBlank(message = "First name is required")
        @Size(max = 100, message = "First name must not exceed 100 characters")
        @Pattern(regexp = "^[\\p{L}][\\p{L} '\\-]*$", message = "First name contains invalid characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(max = 100, message = "Last name must not exceed 100 characters")
        @Pattern(regexp = "^[\\p{L}][\\p{L} '\\-]*$", message = "Last name contains invalid characters")
        String lastName) {

    @Override
    public String toString() {
        return "SignupRequest[email=" + MaskingUtil.maskEmail(email) + ", password=****]";
    }
}
