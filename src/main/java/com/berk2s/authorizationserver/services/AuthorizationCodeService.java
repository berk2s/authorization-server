package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;

import java.net.URI;
import java.util.Set;

public interface AuthorizationCodeService {

    AuthorizationCodeDto getAuthorizationCode(String code, String clientId);

    AuthorizationCodeDto createAuthorizationCode(String clientId,
                                                 URI redirectUri,
                                                 Set<String> scopes,
                                                 String subject,
                                                 String nonce,
                                                 String codeChallenge,
                                                 String codeChallengeMethod);

    void deleteAuthorizationCode(String code);
}
