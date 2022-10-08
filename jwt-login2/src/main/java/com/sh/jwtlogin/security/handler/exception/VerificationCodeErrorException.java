package com.sh.jwtlogin.security.handler.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * 验证码错误异常
 */
public class VerificationCodeErrorException extends AuthenticationException {
    public VerificationCodeErrorException(String msg) {
        super(msg);
    }

    public VerificationCodeErrorException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
