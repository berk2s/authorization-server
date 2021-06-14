package com.berk2s.authorizationserver.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import javax.persistence.Column;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@RedisHash("authorization_code")
public class AuthorizationCode {

    @Id
    private Long id;

    @Indexed
    private String code;

    @Column(name = "client_id")
    @Indexed
    private String clientId;

    @Column(name = "redirect_uri")
    private String redirectUri;

    private String scopes;

    private LocalDateTime expiry;

    private String subject;

    private String nonce;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method")
    private String codeChallengeMethod;

    @Builder
    public AuthorizationCode(String clientId,
                             String redirectUri,
                             String scopes,
                             String code,
                             String subject,
                             String nonce,
                             String codeChallenge,
                             String codeChallengeMethod) {
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
