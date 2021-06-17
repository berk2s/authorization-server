package com.berk2s.authorizationserver.web.models.token;

public enum TokenType {
    JWT("JWT"),
    OPAQUE("OPAQUE"),
    BEARER("Bearer");

    TokenType(String type) {
    }
}
