package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Requested resource does not exist. */
public class ResourceNotFoundException extends BaseException {

    public ResourceNotFoundException(String internalDetail) {
        super(ErrorCode.RESOURCE_NOT_FOUND, internalDetail);
    }

    public ResourceNotFoundException(String internalDetail, Throwable cause) {
        super(ErrorCode.RESOURCE_NOT_FOUND, internalDetail, cause);
    }
}
