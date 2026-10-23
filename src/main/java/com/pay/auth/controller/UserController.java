package com.pay.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.dto.res.ApiResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.security.e2e.E2EEncrypted;
import com.pay.auth.service.UserProfileService;
import com.pay.auth.util.SecurityUtil;

@E2EEncrypted
@RestController
@RequestMapping(ApiPaths.USERS)
@RequiredArgsConstructor
public class UserController {

    private final UserProfileService userProfileService;

    /** Identity comes from the verified token only — never from a path/query parameter (no IDOR). */
    @GetMapping("/me")
    @PreAuthorize("hasAuthority('PROFILE_READ')")
    public ResponseEntity<ApiResponse<UserResponse>> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(ApiResponse.success(userProfileService.getProfile(SecurityUtil.userId(jwt)), "Profile retrieved"));
    }
}
