package com.pay.auth.service;

import java.util.UUID;

import com.pay.auth.constant.enums.RevocationReason;
import com.pay.auth.dao.entity.User;
import com.pay.auth.model.AuthenticatedSession;
import com.pay.auth.model.ClientContext;
import com.pay.auth.model.IssuedTokens;

public interface SessionService {

    IssuedTokens openSession(User user, ClientContext client);

    AuthenticatedSession rotate(String rawRefreshToken, ClientContext client);

    void revokeByAccessTokenJti(String jti, RevocationReason reason);

    void revokeAllForUser(UUID userId, RevocationReason reason);

    boolean isAccessTokenActive(String jti);
}
