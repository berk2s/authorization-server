package com.berk2s.authorizationserver.web.exceptions;

public class InvalidGrantException extends BaseException {
    public InvalidGrantException(String errorDesc) {
        super(errorDesc);
    }
}
