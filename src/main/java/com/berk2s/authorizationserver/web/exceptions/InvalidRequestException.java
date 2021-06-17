package com.berk2s.authorizationserver.web.exceptions;

import lombok.Getter;

public class InvalidRequestException extends BaseException {

    public InvalidRequestException(String errorDesc) {
        super(errorDesc);
    }
}
