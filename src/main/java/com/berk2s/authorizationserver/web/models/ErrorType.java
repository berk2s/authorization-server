package com.berk2s.authorizationserver.web.models;

import lombok.Getter;

@Getter
public enum ErrorType {
    INVALID_REQUEST("invalid_request"),
    INVALID_GRANT("invalid_grant"),
    INVALID_SCOPE("invalid_scope"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
    INVALID_CLIENT("invalid_client"),
    INVALID_TOKEN("invalid_token");

    private final String error;

    private ErrorType(String e) {
        this.error = e;
    }

    @Override
    public String toString() {
        return error;
    }
}
