package com.berk2s.authorizationserver.web.exceptions;

public class InvalidRedirectUriException extends BaseException{
    public InvalidRedirectUriException(String errorDesc) {
        super(errorDesc);
    }
}
