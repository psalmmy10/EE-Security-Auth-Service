package com.pay.auth.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.pay.auth.config.properties.LockoutProperties;
import com.pay.auth.dao.UserRepository;
import com.pay.auth.service.LoginAttemptService;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * REQUIRES_NEW: the failure counter must commit even though the caller then throws.
 * Atomic SQL updates make concurrent attempts race-free without pessimistic locks.
 */
@Service
@RequiredArgsConstructor
public class LoginAttemptServiceImpl implements LoginAttemptService {

    private final UserRepository userRepository;
    private final LockoutProperties lockoutProperties;
    private final Clock clock;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean recordFailure(UUID userId) {
        Instant now = clock.instant();
        userRepository.incrementFailedAttempts(userId, now);
        return userRepository.lockIfThresholdReached(userId, lockoutProperties.maxAttempts(),
                now.plus(lockoutProperties.lockDuration()), now) > 0;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(UUID userId) {
        userRepository.markSuccessfulLogin(userId, clock.instant());
    }
}
