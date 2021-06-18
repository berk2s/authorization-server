package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@Builder
public class RevocationRequestDto implements TokenRequest {

    @NotBlank
    private String token;

    @JsonProperty("token_type_hint")
    private String tokenTypeHint;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    public RevocationRequestDto(String token,
                                String token_type_hint,
                                String client_id,
                                String client_secret) {
        this.token = token;
        this.tokenTypeHint = token_type_hint;
        this.clientId = client_id;
        this.clientSecret = client_secret;
    }


}
