package com.berk2s.authorizationserver.web.exceptions;

public class TokenNotFoundException extends BaseException{
    public TokenNotFoundException(String errorDesc) {
        super(errorDesc);
    }
}
