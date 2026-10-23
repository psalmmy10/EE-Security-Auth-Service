package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Signup could not complete (e.g. email already registered). */
public class RegistrationConflictException extends BaseException {

    public RegistrationConflictException(String internalDetail) {
        super(ErrorCode.REGISTRATION_CONFLICT, internalDetail);
    }

    public RegistrationConflictException(String internalDetail, Throwable cause) {
        super(ErrorCode.REGISTRATION_CONFLICT, internalDetail, cause);
    }
}
