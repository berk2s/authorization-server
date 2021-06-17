package com.berk2s.authorizationserver.web.exceptions;

import lombok.Getter;

@Getter
public abstract class BaseException extends RuntimeException {

    private final String errorDesc;

    public BaseException(String errorDesc) {
        super(errorDesc);
        this.errorDesc = errorDesc;
    }

}
