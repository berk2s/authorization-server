package com.berk2s.authorizationserver.domain;

public enum GrantType {
    AUTHORIZATION_CODE("authorization_code"),
    PASSWORD("password"),
    CLIENT_CREDENTIALS("client_credentials"),
    REFRESH_TOKEN("refresh_token"),
    TOKEN_EXCHANGE("urn:ietf:params:oauth:grant-type:token-exchange");

    private final String grant;

    GrantType(String grant) {
        this.grant = grant;
    }

    public String getGrant() {
        return grant;
    }

    @Override
    public String toString() {
        return grant;
    }
}
