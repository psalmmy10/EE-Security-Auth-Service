package com.pay.auth.dto.req;

import com.pay.auth.constant.enums.RoleName;

import jakarta.validation.constraints.NotNull;

public record AssignRoleRequest(@NotNull(message = "Role is required") RoleName role) {
}
