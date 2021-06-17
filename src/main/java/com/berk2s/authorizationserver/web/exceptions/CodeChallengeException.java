package com.berk2s.authorizationserver.web.exceptions;

public class CodeChallengeException extends BaseException {
    public CodeChallengeException(String errorDesc) {
        super(errorDesc);
    }
}
