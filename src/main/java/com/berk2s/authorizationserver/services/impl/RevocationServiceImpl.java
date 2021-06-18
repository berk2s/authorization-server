package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.services.RevocationService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.RevocationRequestDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class RevocationServiceImpl implements RevocationService {

    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final ClientRepository clientRepository;

    @Override
    public void revokeToken(String authorizationHeader, RevocationRequestDto revocationRequest) {
        ClientCredentialsDto clientCredentials = AuthenticationParser.parseAndValidate(authorizationHeader, revocationRequest);

        String clientId = clientCredentials.getClientId();
        String clientSecret = clientCredentials.getClientSecret();

        Client client = clientRepository.findByClientId(clientCredentials.getClientId())
                .orElseThrow(() -> {
                    log.warn("Client does not exists by given client id [clientId: {}]", clientCredentials.getClientId());
                    throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
                });

        if(client.isConfidential()) {
            clientAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(clientId, clientSecret));
        }

        RefreshTokenDto refreshToken = refreshTokenService.getToken(revocationRequest.getToken());

        log.info("Refresh token is revoked [clientId: {}]", clientCredentials.getClientId());

        refreshTokenRepository.deleteById(refreshToken.getId());
    }
}
