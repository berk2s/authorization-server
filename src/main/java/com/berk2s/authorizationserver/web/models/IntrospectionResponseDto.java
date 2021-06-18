package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IntrospectionResponseDto {

    private boolean active;

    private String scope;

    @JsonProperty("client_id")
    private String clientId;

    private String username;

    @JsonProperty("token_type")
    private String tokenType;

    private long exp;

    private long iat;

    private long nbf;

    private String sub;

    private List<String> aud;

    private String iss;

    private String jti;

}
