package com.berk2s.authorizationserver.web.exceptions;

public class JWTCreatingException extends BaseException{
    public JWTCreatingException(String errorDesc) {
        super(errorDesc);
    }
}
