package com.pay.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.dto.req.AssignRoleRequest;
import com.pay.auth.dto.req.UpdateUserStatusRequest;
import com.pay.auth.dto.res.ApiResponse;
import com.pay.auth.dto.res.PageResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.security.e2e.E2EEncrypted;
import com.pay.auth.service.UserAdministrationService;
import com.pay.auth.util.RequestUtil;
import com.pay.auth.util.SecurityUtil;

import java.util.UUID;

/**
 * Method-level @PreAuthorize replaces (not merges with) class-level rules in Spring Security,
 * so each method states role AND permission explicitly.
 */
@E2EEncrypted
@RestController
@RequestMapping(ApiPaths.ADMIN_USERS)
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserAdministrationService userAdministrationService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('USER_READ')")
    public ResponseEntity<ApiResponse<PageResponse<UserResponse>>> listUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return ResponseEntity.ok(ApiResponse.success(userAdministrationService.listUsers(page, size), "Users retrieved"));
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('USER_READ')")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(ApiResponse.success(userAdministrationService.getUser(userId), "User retrieved"));
    }

    @PatchMapping("/{userId}/status")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('USER_MANAGE')")
    public ResponseEntity<ApiResponse<UserResponse>> updateStatus(@AuthenticationPrincipal Jwt jwt,
                                                                  @PathVariable UUID userId,
                                                                  @Valid @RequestBody UpdateUserStatusRequest request,
                                                                  HttpServletRequest http) {
        UserResponse user = userAdministrationService.updateStatus(
                SecurityUtil.userId(jwt), userId, request, RequestUtil.clientContext(http));
        return ResponseEntity.ok(ApiResponse.success(user, "User status updated"));
    }

    @PostMapping("/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ROLE_MANAGE')")
    public ResponseEntity<ApiResponse<UserResponse>> assignRole(@AuthenticationPrincipal Jwt jwt,
                                                                @PathVariable UUID userId,
                                                                @Valid @RequestBody AssignRoleRequest request,
                                                                HttpServletRequest http) {
        UserResponse user = userAdministrationService.assignRole(
                SecurityUtil.userId(jwt), userId, request.role(), RequestUtil.clientContext(http));
        return ResponseEntity.ok(ApiResponse.success(user, "Role assigned"));
    }

    @DeleteMapping("/{userId}/roles/{role}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ROLE_MANAGE')")
    public ResponseEntity<ApiResponse<UserResponse>> revokeRole(@AuthenticationPrincipal Jwt jwt,
                                                                @PathVariable UUID userId,
                                                                @PathVariable RoleName role,
                                                                HttpServletRequest http) {
        UserResponse user = userAdministrationService.revokeRole(
                SecurityUtil.userId(jwt), userId, role, RequestUtil.clientContext(http));
        return ResponseEntity.ok(ApiResponse.success(user, "Role revoked"));
    }
}
