package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.web.models.TokenRequest;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import java.net.URI;

@Data
@NoArgsConstructor
@Builder
public class TokenRequestDto implements TokenRequest {

    @NotBlank
    @JsonProperty("grant_type")
    private String grantType;

    private String code;

    @JsonProperty("redirect_uri")
    private URI redirectUri;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonProperty("code_verifier")
    private String codeVerifier;

    private String username;

    private String password;

    @JsonProperty("refresh_token")
    private String refreshToken;

    private String scope;

    public TokenRequestDto(String grant_type,
                           String code,
                           URI redirect_uri,
                           String client_id,
                           String client_secret,
                           String code_verifier,
                           String username,
                           String password,
                           String refresh_token,
                           String scope) {
        this.grantType = grant_type;
        this.code = code;
        this.redirectUri = redirect_uri;
        this.clientId = client_id;
        this.clientSecret = client_secret;
        this.codeVerifier = code_verifier;
        this.username = username;
        this.password = password;
        this.refreshToken = refresh_token;
        this.scope = scope;
    }

}
