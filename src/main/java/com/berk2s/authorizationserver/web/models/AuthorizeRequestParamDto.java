package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.net.URI;

@Data
@NoArgsConstructor
@Builder
public class AuthorizeRequestParamDto {

    @NotNull
    @JsonProperty("response_type")
    @Pattern(regexp = "code")
    String responseType;

    @NotNull
    String scope;

    @JsonProperty("client_id")
    @NotNull
    String clientId;

    @JsonProperty("redirect_uri")
    @NotNull
    URI redirectUri;

    String state;

    @JsonProperty("response_mode")
    @Pattern(regexp = "query|form_post")
    String responseMode;

    String nonce;

    @Pattern(regexp = "none|login|consent|select_account")
    String prompt;

    @Pattern(regexp = "page|popup|touch|wap")
    String display;

    @JsonProperty("max_age")
    Long maxAge;

    @JsonProperty("ui_locales")
    String uiLocales;

    @JsonProperty("id_token_hint")
    String idTokenHint;

    @JsonProperty("login_hint")
    String loginHint;

    @JsonProperty("acr_values")
    String acrValues;

    @JsonProperty("code_challenge")
    String codeChallenge;

    @JsonProperty("code_challenge_method")
    @Pattern(regexp = "plain|S256")
    String codeChallengeMethod;

    URI resource;

    public AuthorizeRequestParamDto(String response_type,
                                        String scope,
                                        String clientId,
                                        URI redirectUri,
                                        String state,
                                        String responseMode,
                                        String nonce,
                                        String prompt,
                                        String display,
                                        Long max_age,
                                        String ui_locales,
                                        String id_token_hint,
                                        String login_hint,
                                        String acr_values,
                                        String code_challenge,
                                        String code_challenge_method,
                                        URI resource) {
        this.responseType = response_type;
        this.scope = scope;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.responseMode = responseMode;
        this.nonce = nonce;
        this.prompt = prompt;
        this.display = display;
        this.maxAge = max_age;
        this.uiLocales = ui_locales;
        this.idTokenHint = id_token_hint;
        this.loginHint = login_hint;
        this.acrValues = acr_values;
        this.codeChallenge = code_challenge;
        this.codeChallengeMethod = code_challenge_method;
        this.resource = resource;
    }

}
