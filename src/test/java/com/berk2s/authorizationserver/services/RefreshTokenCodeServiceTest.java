package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.UserType;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.RefreshTokenCodeServiceImpl;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.exceptions.TokenNotFoundException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenCodeServiceTest extends TokenServiceTest {

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Mock
    ClientRepository clientRepository;

    @Mock
    UserRepository userRepository;

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    IdTokenService idTokenService;

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @Mock
    ServerConfiguration serverConfiguration;

    @InjectMocks
    RefreshTokenCodeServiceImpl refreshTokenCodeService;

    TokenRequestDto tokenRequest;
    String encodedAuthorization;
    Client client;
    RefreshToken refreshToken;
    User user;
    UUID clientId;
    UUID userId;

    @BeforeEach
    void setUp() {
        tokenRequest = TokenRequestDto.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .grantType("refresh_token")
                .scope("openid")
                .build();

        clientId = UUID.randomUUID();
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");
        user.setPassword("password");

        refreshToken = new RefreshToken();
        refreshToken.setToken("token");
        refreshToken.setUserType(UserType.END_USER);

        client = new Client();
        client.setId(clientId);
        client.setClientId("clientId");
        client.setClientSecret("clientSecret");
        client.setConfidential(true);
        client.setGrantTypes(Set.of(GrantType.REFRESH_TOKEN));

        encodedAuthorization = AuthenticationParser.encodeBase64("clientId", "clientSecret");

    }


    @DisplayName("Should Refresh Token Code Service Returns Successfully")
    @Test
    void shouldRefreshTokenCodeServiceReturnsSuccessfully() {
        when(refreshTokenRepository.findByToken(any())).thenReturn(Optional.of(refreshToken));

        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
        when(userRepository.findById(any())).thenReturn(Optional.of(user));

        when(accessTokenService.createToken(any())).thenReturn(AccessTokenDto.builder().token("token").build());
        when(refreshTokenService.createToken(any())).thenReturn(RefreshTokenDto.builder().token("token").build());
        when(idTokenService.createToken(any())).thenReturn(IdTokenDto.builder().token("token").build());

        when(clientAuthenticationProvider.authenticate(any())).thenAnswer(a -> {
            Authentication authentication = (Authentication) a.getArguments()[0];

            return new UsernamePasswordAuthenticationToken(authentication.getName(),
                    authentication.getCredentials(),
                    Set.of());
        });

        when(serverConfiguration.getAccessToken()).thenReturn(getAccessTokenConfig());
        when(serverConfiguration.getRefreshToken()).thenReturn(getRefreshTokenConfig());
        when(serverConfiguration.getIdToken()).thenReturn(getIdTokenConfig());

        TokenResponseDto tokenResponse = refreshTokenCodeService.getToken(encodedAuthorization, tokenRequest);

        assertThat(tokenResponse.getAccessToken())
                .isNotNull();

        assertThat(tokenResponse.getRefreshToken())
                .isNotNull();

        assertThat(tokenResponse.getIdToken())
                .isNotNull();

        assertThat(tokenResponse.getExpiresIn())
                .isNotNull();

        verify(refreshTokenRepository, times(1)).findByToken(any());

        verify(clientRepository, times(1)).findByClientId(any());
        verify(userRepository, times(1)).findById(any());

        verify(accessTokenService, times(1)).createToken(any());
        verify(refreshTokenService, times(1)).createToken(any());
        verify(idTokenService, times(1)).createToken(any());

        verify(clientAuthenticationProvider, times(1)).authenticate(any());

        verify(serverConfiguration, times(1)).getAccessToken();
        verify(serverConfiguration, times(1)).getRefreshToken();
        verify(serverConfiguration, times(1)).getIdToken();
    }



    @DisplayName("Invalid Client Id Throws Exception")
    @Test
    void invalidClientIdThrowsException() {
        TokenResponseDto tokenResponse = null;

        try {
            tokenResponse = refreshTokenCodeService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Insufficient Client Grant Type Throws Exception")
    @Test
    void insufficientClientGrantTypeThrowsException() {
        TokenResponseDto tokenResponse = null;

        try {
            client.setGrantTypes(Set.of());
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

            tokenResponse = refreshTokenCodeService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidGrantException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_REFRESH_TOKEN.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }
            verify(clientRepository, times(1)).findByClientId(any());

        }
    }

    @DisplayName("Invalid Token Throws Exception")
    @Test
    void invalidTokenThrowsException() {
        TokenResponseDto tokenResponse = null;

        try {
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

            tokenResponse = refreshTokenCodeService.getToken(encodedAuthorization, tokenRequest);
        } catch (TokenNotFoundException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_TOKEN.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }
            verify(clientRepository, times(1)).findByClientId(any());

        }
    }


}