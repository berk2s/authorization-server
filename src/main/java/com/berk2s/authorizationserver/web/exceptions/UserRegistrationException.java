package com.berk2s.authorizationserver.web.exceptions;

public class UserRegistrationException extends BaseException{
    public UserRegistrationException(String errorDesc) {
        super(errorDesc);
    }
}
