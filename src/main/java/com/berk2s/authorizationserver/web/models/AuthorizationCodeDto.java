package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationCodeDto {

    private Long id;

    private String clientId;

    private URI redirectUri;

    private Set<String> scopes;

    private String code;

    private LocalDateTime expiry;

    private String subject;

    private String nonce;

    @JsonProperty("code_challenge")
    private String codeChallenge;

    @JsonProperty("code_challenge_method")
    private String codeChallengeMethod;

    @Builder
    public AuthorizationCodeDto(Long id,
                                String clientId,
                                URI redirectUri,
                                Set<String> scopes,
                                String code,
                                String subject,
                                String nonce,
                                String codeChallenge,
                                String codeChallengeMethod) {
        this.id = id;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.code = code;
        this.subject = subject;
        this.nonce = nonce;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiry = LocalDateTime.now().plusMinutes(2);
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(getExpiry());
    }

}
