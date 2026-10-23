package com.pay.auth.constant.enums;

import com.pay.auth.constant.SecurityConstants;

public enum RoleName {
    USER,
    ADMIN;

    public String authority() {
        return SecurityConstants.ROLE_PREFIX + name();
    }
}
