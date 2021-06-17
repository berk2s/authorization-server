package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.services.AuthorizationCodeTokenService;
import com.berk2s.authorizationserver.utils.AuthorizationParser;
import com.berk2s.authorizationserver.utils.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.TokenRequestDto;
import com.berk2s.authorizationserver.web.models.TokenResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthorizationCodeTokenImpl implements AuthorizationCodeTokenService {

    private final ClientRepository clientRepository;

    @Override
    public TokenResponseDto getToken(String authorizationHeader, TokenRequestDto tokenRequest) {
        ClientCredentialsDto clientCredentials = AuthorizationParser.basicParser(authorizationHeader);

        Client client = clientRepository.findByClientId(clientCredentials.getClientId())
                .orElseThrow(() -> {
                    log.warn("Client does not exists by given client id [clientId: {}]", clientCredentials.getClientId());
                    throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
                });

        if (!client.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
            log.warn("The Client request for authorization but it doesn't has authorization_code grant [clientId: {}]", client.getClientId());
            throw new InvalidGrantException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc());
        }

        return null;
    }
}
