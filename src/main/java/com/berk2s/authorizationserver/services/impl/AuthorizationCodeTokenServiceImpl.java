package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.*;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.exceptions.InvalidRequestException;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.token.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Locale;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthorizationCodeTokenServiceImpl implements AuthorizationCodeTokenService {

    private final ClientRepository clientRepository;
    private final AuthorizationCodeService authorizationCodeService;
    private final PKCEService pkceService;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final ServerConfiguration serverConfiguration;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final IdTokenService idTokenService;


    @Override
    public TokenResponseDto getToken(String authorizationHeader, TokenRequestDto tokenRequest) {
        ClientCredentialsDto clientCredentials = AuthenticationParser.parseAndValidate(authorizationHeader, tokenRequest);

        Client client = clientRepository.findByClientId(clientCredentials.getClientId())
                .orElseThrow(() -> {
                    log.warn("Client does not exists by given client id [clientId: {}]", clientCredentials.getClientId());
                    throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
                });

        if (!client.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
            log.warn("The Client request for authorization but it doesn't has authorization_code grant [clientId: {}]", client.getClientId());
            throw new InvalidGrantException(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc());
        }

        AuthorizationCodeDto authorizationCode =
                authorizationCodeService.getAuthorizationCode(tokenRequest.getCode(), client.getClientId());

        if(StringUtils.isNotBlank(authorizationCode.getCodeChallenge())) {
            pkceService.verifyCodeChallenge(authorizationCode.getCodeChallengeMethod(),
                    tokenRequest.getCodeVerifier(),
                    authorizationCode.getCodeChallenge());
        } else {
            if(!client.isConfidential()) {
                log.warn("Public Client tried request without PKCE and code challenge");
                throw new InvalidRequestException(ErrorDesc.INVALID_CLIENT_TYPE.getDesc());
            } else {
                clientAuthenticationProvider
                        .authenticate(new UsernamePasswordAuthenticationToken(clientCredentials.getClientId(), clientCredentials.getClientSecret()));
            }
        }

        User user = userRepository
                .findById(UUID.fromString(authorizationCode.getSubject()))
                .orElseThrow(() -> {
                    log.warn("Cannot find user by given user id [userId: {}]", authorizationCode.getSubject());
                    throw new InvalidGrantException(ErrorDesc.INVALID_CODE_SUBJECT.getDesc());
                });

        Duration accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();
        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();
        Duration idTokenDuration = serverConfiguration.getIdToken().getLifetime();

        SecurityUserDetails securityUserDetails = new SecurityUserDetails(user);

        TokenCommand refreshTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(authorizationCode.getScopes())
                .duration(refreshTokenDuration)
                .build();

        TokenCommand accessTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(authorizationCode.getScopes())
                .nonce(authorizationCode.getNonce())
                .duration(accessTokenDuration)
                .build();

        TokenCommand idTokenCmd = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId(client.getClientId())
                .scopes(authorizationCode.getScopes())
                .nonce(authorizationCode.getNonce())
                .duration(idTokenDuration)
                .build();

        RefreshTokenDto refreshToken = refreshTokenService.createToken(refreshTokenCmd);

        AccessTokenDto accessToken = accessTokenService.createToken(accessTokenCmd);

        IdTokenDto idToken = null;

        if(authorizationCode.getScopes().stream().map(String::toUpperCase).anyMatch(s -> s.contains(ScopeConfig.OPENID.name()))) {
            idToken = idTokenService.createToken(idTokenCmd);
        }

        log.info("Token response is created [grantType: authorization_code, clientId: {}, userId: {}]", client.getClientId(), user.getId().toString());

        return TokenResponseDto.builder()
                .accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken())
                .idToken(idToken != null ? idToken.getToken() : null)
                .tokenType(TokenType.BEARER.name())
                .expiresIn(accessTokenDuration.toSeconds())
                .build();
    }
}
