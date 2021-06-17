package com.berk2s.authorizationserver.web.exceptions;

import lombok.Getter;

@Getter
public class InvalidClientException extends BaseException {

    public InvalidClientException(String message) {
        super(message);
    }
}
