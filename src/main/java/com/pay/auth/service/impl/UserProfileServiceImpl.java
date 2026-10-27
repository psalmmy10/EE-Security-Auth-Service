package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.exception.ResourceNotFoundException;
import com.pay.auth.mapper.UserMapper;
import com.pay.auth.service.UserProfileService;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserProfileServiceImpl implements UserProfileService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @Override
    @Transactional(readOnly = true)
    public UserResponse getProfile(UUID userId) {
        return userRepository.findWithRolesById(userId)
                .map(userMapper::toResponse)
                .orElseThrow(() -> {
                    log.warn("Profile lookup failed: user not found (userId={})", userId);
                    return new ResourceNotFoundException("user " + userId);
                });
    }
}