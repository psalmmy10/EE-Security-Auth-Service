package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Temporary brute-force lock. Only surfaced when the correct password was supplied. */
public class AccountLockedException extends BaseException {

    public AccountLockedException(String internalDetail) {
        super(ErrorCode.ACCOUNT_LOCKED, internalDetail);
    }

    public AccountLockedException(String internalDetail, Throwable cause) {
        super(ErrorCode.ACCOUNT_LOCKED, internalDetail, cause);
    }
}
