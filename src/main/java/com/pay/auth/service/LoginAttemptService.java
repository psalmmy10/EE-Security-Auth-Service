package com.pay.auth.service;

import java.util.UUID;

public interface LoginAttemptService {

    /** @return true if this failure caused the account to be locked */
    boolean recordFailure(UUID userId);

    void recordSuccess(UUID userId);
}
