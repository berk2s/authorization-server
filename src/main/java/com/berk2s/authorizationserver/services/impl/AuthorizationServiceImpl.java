package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AuthorizationCodeService;
import com.berk2s.authorizationserver.services.AuthorizationService;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.exceptions.*;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import com.berk2s.authorizationserver.web.models.AuthorizeRequestParamDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthorizationServiceImpl implements AuthorizationService {

    private final ClientRepository clientRepository;
    private final AuthorizationCodeService authorizationCodeService;

    @Override
    public URI authorizeRequest(AuthorizeRequestParamDto params, SecurityUserDetails securityUserDetails) {
        try {
            if (securityUserDetails == null || securityUserDetails.getId() == null) {
                log.warn("Invalid security user details [clientId: {}]", params.getClientId());
                throw new InvalidSecurityUserDetailsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
            }

            Client client = clientRepository
                    .findByClientId(params.getClientId())
                    .orElseThrow(() -> {
                        log.warn("Invalid client id [clientId: {}]", params.getClientId());
                        throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
                    });


            if (!client.getRedirectUris().contains(params.getRedirectUri())) {
                log.warn("Invalid redirect uri, it doesn't contain in Client's URI list [clientId: {}]", params.getClientId());
                throw new InvalidRedirectUriException(ErrorDesc.INVALID_REDIRECT_URI.getDesc());
            }

            if (!client.isConfidential() && (params.getCodeChallenge() == null || params.getCodeChallenge().isBlank())) {
                log.warn("Public Client tried request without PKCE [clientId: {}]", params.getClientId());
                return redirectError(params.getRedirectUri(), ErrorType.INVALID_REQUEST.getError(), URLEncoder.encode(ErrorDesc.INVALID_CLIENT_TYPE.getDesc(), StandardCharsets.UTF_8), params.getState());
            }

            if(!client.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
                log.warn("The Client request for authorization but it doesn't has authorization_code grant [clientId: {}]", params.getClientId());
                return redirectError(params.getRedirectUri(), ErrorType.INVALID_GRANT.getError(), URLEncoder.encode(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc(), StandardCharsets.UTF_8), params.getState());
            }

            Set<String> scopes = new HashSet<>(Arrays.asList(params.getScope().split(" ")));

            AuthorizationCodeDto authorizationCode =
                    authorizationCodeService.createAuthorizationCode(
                            params.getClientId(),
                            params.getRedirectUri(),
                            scopes,
                            securityUserDetails.getId().toString(),
                            params.getNonce(),
                            params.getCodeChallenge(),
                            params.getCodeChallengeMethod());

            log.info("Redirect uri created. [clientId: {}, uri: {}, code: {}, state: {}]", params.getClientId(),
                    params.getRedirectUri().toString(),
                    authorizationCode.getCode(),
                    params.getState());

            return new URI(params.getRedirectUri().toString()
                    + "?code="
                    + authorizationCode.getCode()
                    + "&state="
                    + params.getState());

        } catch (URISyntaxException e) {
            log.warn(e.getMessage() + "[clientId: {}]", params.getClientId());
            throw new ServerException(ErrorDesc.SERVER_ERROR.getDesc());
        }
    }

    private URI redirectError(URI redirectUri, String errorType, String errorDescription, String state) throws URISyntaxException {
        return new URI(redirectUri.toString()
                + "?error="
                + errorType
                + "&error_description="
                + errorDescription
                + "&state="
                + state);
    }

}
