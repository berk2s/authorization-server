package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.security.UserAuthenticationProvider;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.IdTokenService;
import com.berk2s.authorizationserver.services.PasswordCodeTokenService;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class PasswordCodeTokenServiceImpl implements PasswordCodeTokenService {

    private final ClientRepository clientRepository;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final UserAuthenticationProvider userAuthenticationProvider;
    private final UserRepository userRepository;
    private final ServerConfiguration serverConfiguration;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final IdTokenService idTokenService;

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

        clientAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(clientId, clientSecret));

        if (!client.isConfidential()) {
            log.warn("Public Client tried to request with password [clientId: {}]", clientId);
            throw new InvalidClientException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_PASSWORD.getDesc());
        }

        if (!client.getGrantTypes().contains(GrantType.PASSWORD)) {
            log.warn("Client tried to request password but it is not permitted to password [clientId: {}]", clientId);
            throw new InvalidGrantException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_PASSWORD.getDesc());
        }

        String username = tokenRequest.getUsername();
        String password = tokenRequest.getPassword();

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Cannot find user by given username [username: {}]", username);
                    throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
                });

        userAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        Duration accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();
        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();
        Duration idTokenDuration = serverConfiguration.getIdToken().getLifetime();

        SecurityUserDetails securityUserDetails = new SecurityUserDetails(user);

        Set<String> scopes = new HashSet<>();

        if (tokenRequest.getScope() != null) {
            Collections.addAll(scopes, tokenRequest.getScope().split(" "));
        }

        TokenCommand refreshTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(scopes)
                .duration(refreshTokenDuration)
                .build();

        TokenCommand accessTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(scopes)
                .nonce(null)
                .duration(accessTokenDuration)
                .build();

        TokenCommand idTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(scopes)
                .nonce(null)
                .duration(idTokenDuration)
                .build();

        RefreshTokenDto refreshToken = refreshTokenService.createToken(refreshTokenCmd);

        AccessTokenDto accessToken = accessTokenService.createToken(accessTokenCmd);

        IdTokenDto idToken = null;

        if (scopes.stream().map(String::toUpperCase).anyMatch(s -> s.contains(ScopeConfig.OPENID.name()))) {
            idToken = idTokenService.createToken(idTokenCmd);
        }

        log.info("Token response is created [grantType: password, clientId: {}, userId: {}]", client.getClientId(), user.getId().toString());

        return TokenResponseDto.builder()
                .accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken())
                .idToken(idToken != null ? idToken.getToken() : null)
                .tokenType(TokenType.BEARER.name())
                .expiresIn(accessTokenDuration.toSeconds())
                .build();
    }

}
