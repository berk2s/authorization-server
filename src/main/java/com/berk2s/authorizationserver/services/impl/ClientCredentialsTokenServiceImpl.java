package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.ClientCredentialsTokenService;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.*;
import io.micrometer.core.instrument.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class ClientCredentialsTokenServiceImpl implements ClientCredentialsTokenService {

    private final ClientRepository clientRepository;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final ServerConfiguration serverConfiguration;
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public TokenResponseDto getToken(String authorizationHeader, TokenRequestDto tokenRequest) {
        ClientCredentialsDto clientCredentials = AuthenticationParser.parseAndValidate(authorizationHeader, tokenRequest);

        String clientId = clientCredentials.getClientId();
        String clientSecret = clientCredentials.getClientSecret();

        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> {
                    log.warn("Client does not exists by given client id [clientId: {}]", clientId);
                    throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
                });

        if(!client.isConfidential()) {
            log.warn("Public Client tried to request with client_credentials [clientId: {}]", clientId);
            throw new InvalidClientException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc());
        }

        if(!client.getGrantTypes().contains(GrantType.CLIENT_CREDENTIALS)) {
            log.warn("Client tried to request client_credentials but it is not permitted to client_credentials [clientId: {}]", clientId);
            throw new InvalidGrantException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc());
        }

        clientAuthenticationProvider
                .authenticate(new UsernamePasswordAuthenticationToken(clientId, clientSecret));

        Set<String> scopesSet = new HashSet<>();

        if(StringUtils.isNotBlank(tokenRequest.getScope())) {
            scopesSet = new HashSet<>(Arrays.asList(tokenRequest.getScope().split(" ")));
        }

        Duration accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();
        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();

        SecurityClientDetails securityClientDetails = new SecurityClientDetails(client);

        TokenCommand accessTokenCmd = TokenCommand.builder()
                .clientId(clientId)
                .scopes(scopesSet)
                .duration(accessTokenDuration)
                .userDetails(securityClientDetails)
                .build();


        TokenCommand refreshTokenCmd = TokenCommand.builder()
                .clientId(clientId)
                .scopes(scopesSet)
                .duration(refreshTokenDuration)
                .userDetails(securityClientDetails)
                .build();

        AccessTokenDto accessToken = accessTokenService.createToken(accessTokenCmd);
        RefreshTokenDto refreshToken = refreshTokenService.createToken(refreshTokenCmd);

        log.info("Token response is created [grantType: client_credentials, clientId: {}]", client.getClientId());

        return TokenResponseDto.builder()
                .accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken())
                .expiresIn(1L)
                .tokenType(TokenType.BEARER.name())
                .build();
    }
}
