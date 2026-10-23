package com.pay.auth.service;

import java.time.Instant;

import com.pay.auth.entity.User;
import com.pay.auth.model.AccessToken;

/** Token minting only — no persistence, no policy. Swappable (e.g. for an external AS). */
public interface TokenService {

    AccessToken issueAccessToken(User user, String jti, Instant issuedAt);

    String newRefreshToken();

    String hashRefreshToken(String rawRefreshToken);
}
