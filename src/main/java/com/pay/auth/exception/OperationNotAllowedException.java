package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Business rule prevents the operation (e.g. an admin demoting themselves). */
public class OperationNotAllowedException extends BaseException {

    public OperationNotAllowedException(String internalDetail) {
        super(ErrorCode.OPERATION_NOT_ALLOWED, internalDetail);
    }

    public OperationNotAllowedException(String internalDetail, Throwable cause) {
        super(ErrorCode.OPERATION_NOT_ALLOWED, internalDetail, cause);
    }
}
