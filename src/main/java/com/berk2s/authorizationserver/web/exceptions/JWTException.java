package com.berk2s.authorizationserver.web.exceptions;

public class JWTException extends BaseException{
    public JWTException(String errorDesc) {
        super(errorDesc);
    }
}
