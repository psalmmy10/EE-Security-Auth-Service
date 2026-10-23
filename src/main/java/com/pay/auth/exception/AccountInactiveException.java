package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Account disabled or locked by an administrator. */
public class AccountInactiveException extends BaseException {

    public AccountInactiveException(String internalDetail) {
        super(ErrorCode.ACCOUNT_INACTIVE, internalDetail);
    }

    public AccountInactiveException(String internalDetail, Throwable cause) {
        super(ErrorCode.ACCOUNT_INACTIVE, internalDetail, cause);
    }
}
