package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pay.auth.dao.repository.UserRepository;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.exception.ResourceNotFoundException;
import com.pay.auth.mapper.UserMapper;
import com.pay.auth.service.UserProfileService;

import java.util.UUID;

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
                .orElseThrow(() -> new ResourceNotFoundException("user " + userId));
    }
}
