package com.berk2s.authorizationserver.web.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;

@Getter
public class InvalidSecurityUserDetailsException extends BadCredentialsException {

    private final String errorDesc;

    public InvalidSecurityUserDetailsException(String errorDesc) {
        super(errorDesc);
        this.errorDesc = errorDesc;
    }

}
