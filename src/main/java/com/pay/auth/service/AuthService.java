package com.pay.auth.service;

import java.util.UUID;

import com.pay.auth.dto.req.LoginRequest;
import com.pay.auth.dto.req.RefreshTokenRequest;
import com.pay.auth.dto.req.SignupRequest;
import com.pay.auth.dto.res.AuthResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.model.ClientContext;

/** Facade over credential verification, session issuance and auditing. */
public interface AuthService {

    UserResponse signup(SignupRequest request, ClientContext client);

    AuthResponse login(LoginRequest request, ClientContext client);

    AuthResponse refresh(RefreshTokenRequest request, ClientContext client);

    void logout(UUID userId, String accessTokenJti, ClientContext client);

    void logoutAll(UUID userId, ClientContext client);
}
