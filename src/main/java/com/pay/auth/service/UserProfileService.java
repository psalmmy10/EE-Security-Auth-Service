package com.pay.auth.service;

import java.util.UUID;

import com.pay.auth.dto.res.UserResponse;

/** Self-service operations (ISP: kept apart from administrative capabilities). */
public interface UserProfileService {

    UserResponse getProfile(UUID userId);
}
