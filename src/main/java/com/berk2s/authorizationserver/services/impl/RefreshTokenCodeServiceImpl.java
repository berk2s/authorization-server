package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.UserType;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.IdTokenService;
import com.berk2s.authorizationserver.services.RefreshTokenCodeService;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.exceptions.TokenNotFoundException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class RefreshTokenCodeServiceImpl implements RefreshTokenCodeService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final ClientRepository clientRepository;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final IdTokenService idTokenService;
    private final ServerConfiguration serverConfiguration;
    private final UserRepository userRepository;

    @Override
    public TokenResponseDto getToken(String authorizationHeader, TokenRequestDto tokenRequest) {
        ClientCredentialsDto clientCredentials = AuthenticationParser.parseAndValidate(authorizationHeader, tokenRequest);

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

        if(!client.getGrantTypes().contains(GrantType.REFRESH_TOKEN)) {
            log.warn("Client tried to request refresh_token but it is not permitted to refresh_token [clientId: {}]", clientId);
            throw new InvalidGrantException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_REFRESH_TOKEN.getDesc());
        }

        RefreshToken refreshToken = refreshTokenRepository.findByToken(tokenRequest.getRefreshToken())
                .orElseThrow(() -> {
                   log.warn("Cannot find refresh token by given token [token: {}]", tokenRequest.getRefreshToken());
                    throw new TokenNotFoundException(ErrorDesc.INVALID_TOKEN.getDesc());
                });


        Duration accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();
        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();
        Duration idTokenDuration = serverConfiguration.getIdToken().getLifetime();

        SecurityDetails securityDetails = getSecurityDetails(refreshToken, client);

        Set<String> scopes = new HashSet<>();

        if(tokenRequest.getScope() != null) {
            scopes = new HashSet<>(Arrays.asList(tokenRequest.getScope().split(" ")));
        }

        TokenCommand refreshTokenCmd = TokenCommand.builder()
                .userDetails(securityDetails)
                .clientId(client.getClientId())
                .scopes(scopes)
                .duration(refreshTokenDuration)
                .build();

        TokenCommand accessTokenCmd = TokenCommand.builder()
                .userDetails(securityDetails)
                .clientId(client.getClientId())
                .scopes(scopes)
                .nonce(null)
                .duration(accessTokenDuration)
                .build();

        TokenCommand idTokenCmd = null;

        RefreshTokenDto refreshTokenDto = refreshTokenService.createToken(refreshTokenCmd);

        AccessTokenDto accessTokenDto = accessTokenService.createToken(accessTokenCmd);

        IdTokenDto idTokenDto = null;

        if (refreshToken.getUserType().equals(UserType.END_USER)) {
            scopes.add("openid");

            idTokenCmd = TokenCommand.builder()
                    .userDetails(securityDetails)
                    .clientId(client.getClientId())
                    .scopes(scopes)
                    .nonce(null)
                    .duration(idTokenDuration)
                    .build();

            if(scopes.stream().map(String::toUpperCase).anyMatch(s -> s.contains(ScopeConfig.OPENID.name()))) {
                idTokenDto = idTokenService.createToken(idTokenCmd);
            }
        }


        log.info("Token response is created [grantType: refresh_token, clientId: {}, userId: {}]", client.getClientId(), securityDetails.getId().toString());

        return TokenResponseDto.builder()
                .accessToken(accessTokenDto.getToken())
                .refreshToken(refreshTokenDto.getToken())
                .idToken(idTokenDto != null ? idTokenDto.getToken() : null)
                .tokenType(TokenType.BEARER.name())
                .expiresIn(accessTokenDuration.toSeconds())
                .build();
    }

    private SecurityDetails getSecurityDetails(RefreshToken refreshToken, Client client) {
        UUID subject = refreshToken.getSubject();
        if(refreshToken.getUserType().equals(UserType.END_USER)) {
            return new SecurityUserDetails(userRepository.findById(subject)
                    .orElseThrow(() -> {
                        log.warn("Cannot find user by given id [userId: {}]", subject);
                        throw new InvalidGrantException(ErrorDesc.INVALID_CODE_SUBJECT.getDesc());
                    }));
        }

        return new SecurityClientDetails(client);
    }
}
