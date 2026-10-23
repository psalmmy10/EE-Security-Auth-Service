package com.pay.auth.model;

import com.pay.auth.dao.entity.User;

public record AuthenticatedSession(User user, IssuedTokens tokens) {

    @Override
    public String toString() {
        return "AuthenticatedSession[userId=" + user.getId() + ", tokens=" + tokens + "]";
    }
}
