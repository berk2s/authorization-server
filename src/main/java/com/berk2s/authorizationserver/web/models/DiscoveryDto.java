package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DiscoveryDto {
    private String issuer;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("userinfo_endpoint")
    private String userinfoEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("registration_endpoint")
    private String registrationEndpoint;

    @JsonProperty("introspection_endpoint")
    private String introspectionEndpoint;

    @JsonProperty("revocation_endpoint")
    private String revocationEndpoint;

    @JsonProperty("device_authorization_endpoint")
    private String deviceAuthorizationEndpoint;

    @JsonProperty("request_object_endpoint")
    private String requestObjectEndpoint;

    @JsonProperty("pushed_authorization_request_endpoint")
    private String pushedAuthorizationRequestEndpoint;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported = new ArrayList<>();

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported = new ArrayList<>();

    @JsonProperty("response_modes_supported")
    private List<String> responseModesSupported = new ArrayList<>();

    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported = new ArrayList<>();

    @JsonProperty("acr_values_supported")
    private List<String> acrValuesSupported = new ArrayList<>();

    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported = new ArrayList<>();

    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported = new ArrayList<>();

    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported = new ArrayList<>();

    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    private List<String> tokenEndpointAuthSigningAlgValuesSupported = new ArrayList<>();

    @JsonProperty("claims_supported")
    private List<String> claimsSupported = new ArrayList<>();

    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported = new ArrayList<>();
}
