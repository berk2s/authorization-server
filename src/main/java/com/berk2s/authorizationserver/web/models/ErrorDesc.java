package com.berk2s.authorizationserver.utils;

import lombok.Getter;

@Getter
public enum ErrorDesc {
    NO_SUCH_ALGORITHIM("No such algorithm"),
    BAD_CREDENTIALS("Bad credentials"),
    INVALID_CLIENT("Invalid oauth client"),
    INVALID_TOKEN("Invalid access_token or refresh_token"),
    SERVER_ERROR("Server error"),
    MISSING_CLIENT_CREDENTIALS("Missing client credentials"),
    INVALID_CLIENT_CREDENTIALS("Invalid client credentials"),
    EXPIRED_OR_INVALID_TOKEN("The token has expired or is not yet valid"),
    /**
     * AuthorizationCodeService Exception Descriptions
     */
    EXPIRED_CODE("Authorization Code is expired"),
    INVALID_CODE("Authorization Code does not match the client_id"),
    NULL_CODE("Invalid Authorization Code"),

    /**
     * ProofKeyForCodeExchangeVerifierService Exception Descriptions
     */
    MISSING_CODE_VERIFIER("The code_verifier must be present"),
    INVALID_CODE_VERIFIER("Invalid code_verifier"),
    INVALID_CHALLENGE_METHOD("Invalid challenge_method"),
    INVALID_CODE_CHALLENGE("Invalid code_challenge"),

    /**
     * AuthorizationCodeTokenService Exception Descriptions
     */
    INSUFFICIENT_CLIENT_GRANT_CODE("The Client does not support authorization_code grant type"),
    INVALID_CODE_SUBJECT("Invalid code subject"),
    INVALID_CLIENT_TYPE("PKCE with code challenge is required for public Clients"),
    /**
     * ClientCredentialsTokenService Exception Descriptions
     */
    INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS("The Client does not support client_credentials grant type"),
    /**
     * PasswordTokenService Exception Descriptions
     */
    INSUFFICIENT_CLIENT_GRANT_PASSWORD("The Client does not support password grant type"),
    /**
     * RefreshTokenService Exception Descriptions
     */
    INSUFFICIENT_CLIENT_GRANT_REFRESH_TOKEN("The Client does not support refresh_token grant type"),
    INVALID_TOKEN_SUBJECT("Invalid token subject"),
    /**
     * AuthorizationService Exception Descriptions
     */
    INVALID_REDIRECT_URI("Invalid redirect uri"),
    /**
     * RutinimUserDetailsService Exception Descriptions
     */
    INVALID_USER("Invalid user");

    private final String desc;

    private ErrorDesc(String desc) {
        this.desc = desc;
    }

    @Override
    public String toString() {
        return desc;
    }
}
