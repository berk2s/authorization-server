package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.UserType;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.IntrospectionService;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.exceptions.ServerException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.IntrospectionRequestDto;
import com.berk2s.authorizationserver.web.models.IntrospectionResponseDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class IntrospectionServiceImpl implements IntrospectionService {

    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final RefreshTokenService refreshTokenService;
    private final JWTService jwtService;
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;

    @Override
    public IntrospectionResponseDto getTokenInfo(String authenticationHeader, IntrospectionRequestDto introspectionRequest) {
        try {
            ClientCredentialsDto clientCredentials = AuthenticationParser.basicParser(authenticationHeader);

            clientAuthenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(clientCredentials.getClientId(), clientCredentials.getClientSecret()));

            String token = introspectionRequest.getToken();

            if (getTokenType(token).equals(TokenType.JWT)) {
                JWTClaimsSet jwtClaimsSet = jwtService.parseAndValidate(token);

                return IntrospectionResponseDto.builder()
                        .active(true)
                        .clientId(clientCredentials.getClientId())
                        .username(jwtClaimsSet.getStringClaim("username"))
                        .scope(jwtClaimsSet.getStringClaim("scope"))
                        .exp(jwtClaimsSet.getExpirationTime().getTime())
                        .build();
            } else {
                RefreshTokenDto refreshToken = refreshTokenService.getToken(token);

                return IntrospectionResponseDto.builder()
                        .active(true)
                        .clientId(refreshToken.getClientId())
                        .username(getUsername(refreshToken))
                        .scope("refresh_token")
                        .exp(refreshToken.getExpiryDateTime().getSecond())
                        .build();
            }
        } catch (ParseException ex) {
            log.warn("Parse Exception while parsing jwt: {}", ex.getMessage());
            throw new ServerException(ErrorDesc.SERVER_ERROR.getDesc());
        }

    }

    private String getUsername(RefreshTokenDto refreshToken) {
        UUID subject = UUID.fromString(refreshToken.getSubject());

        if(refreshToken.getUserType().equals(UserType.END_USER)) {
            User user = userRepository
                    .findById(subject)
                    .orElseThrow(() -> {
                       log.warn("Cannot find user by id [userId: {}]", subject.toString());
                        throw new InvalidGrantException(ErrorDesc.INVALID_CODE_SUBJECT.getDesc());
                    });

            return user.getUsername();
        } else {
            Client client = clientRepository
                    .findById(subject)
                    .orElseThrow(() -> {
                        log.warn("Cannot find client by id [id: {}]", subject.toString());
                        throw new InvalidGrantException(ErrorDesc.INVALID_CLIENT.getDesc());
                    });

            return client.getClientId();
        }
    }

    private TokenType getTokenType(String token) {
        if(token.matches("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")) {
            return TokenType.JWT;
        } else {
            return TokenType.OPAQUE;
        }
    }

}
