package com.pay.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.dto.req.LoginRequest;
import com.pay.auth.dto.req.RefreshTokenRequest;
import com.pay.auth.dto.req.SignupRequest;
import com.pay.auth.dto.res.ApiResponse;
import com.pay.auth.dto.res.AuthResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.security.e2e.E2EEncrypted;
import com.pay.auth.service.AuthService;
import com.pay.auth.util.RequestUtil;
import com.pay.auth.util.SecurityUtil;

/** Thin HTTP adapter: no business logic, no crypto — both live in their own layers. */
@Slf4j
@E2EEncrypted
@RestController
@RequestMapping(ApiPaths.AUTH)
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserResponse>> signup(@Valid @RequestBody SignupRequest request,
                                                            HttpServletRequest http) {
        UserResponse user = authService.signup(request, RequestUtil.clientContext(http));
        log.info("HTTP 201 signup (userId={})", user.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(user, "Registration successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request,
                                                           HttpServletRequest http) {
        AuthResponse auth = authService.login(request, RequestUtil.clientContext(http));
        log.info("HTTP 200 login (userId={})", auth.user().id());
        return ResponseEntity.ok(ApiResponse.success(auth, "Login successful"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request,
                                                             HttpServletRequest http) {
        AuthResponse auth = authService.refresh(request, RequestUtil.clientContext(http));
        log.debug("HTTP 200 refresh (userId={})", auth.user().id());
        return ResponseEntity.ok(ApiResponse.success(auth, "Token refreshed"));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        authService.logout(SecurityUtil.userId(jwt), jwt.getId(), RequestUtil.clientContext(http));
        log.info("HTTP 200 logout");
        return ResponseEntity.ok(ApiResponse.success(null, "Logged out"));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAll(@AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        authService.logoutAll(SecurityUtil.userId(jwt), RequestUtil.clientContext(http));
        log.info("HTTP 200 logout-all");
        return ResponseEntity.ok(ApiResponse.success(null, "Logged out of all sessions"));
    }
}