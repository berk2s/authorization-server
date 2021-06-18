package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.security.UserAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.PasswordCodeTokenServiceImpl;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
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
class PasswordCodeTokenServiceTest extends TokenServiceTest {

    @Mock
    ClientRepository clientRepository;

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @Mock
    UserAuthenticationProvider userAuthenticationProvider;

    @Mock
    UserRepository userRepository;

    @Mock
    ServerConfiguration serverConfiguration;

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    IdTokenService idTokenService;

    @InjectMocks
    PasswordCodeTokenServiceImpl passwordTokenService;

    TokenRequestDto tokenRequest;
    String encodedAuthorization;
    Client client;
    User user;
    UUID clientId;
    UUID userId;

    @BeforeEach
    void setUp() {
        tokenRequest = TokenRequestDto.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .grantType("password")
                .scope("openid")
                .build();

        clientId = UUID.randomUUID();
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");
        user.setPassword("password");

        client = new Client();
        client.setId(clientId);
        client.setClientId("clientId");
        client.setClientSecret("clientSecret");
        client.setConfidential(true);
        client.setGrantTypes(Set.of(GrantType.PASSWORD));

        encodedAuthorization = AuthenticationParser.encodeBase64("clientId", "clientSecret");

    }


    @DisplayName("Should Password Token Returns Successfully")
    @Test
    void shouldPasswordTokenReturnsSuccessfully() {

        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
        when(clientAuthenticationProvider.authenticate(any())).thenAnswer(a -> {
            Authentication authentication = (Authentication) a.getArguments()[0];

            return new UsernamePasswordAuthenticationToken(authentication.getName(),
                    authentication.getCredentials(),
                    Set.of());
        });
        when(userAuthenticationProvider.authenticate(any())).thenAnswer(a -> {
            Authentication authentication = (Authentication) a.getArguments()[0];

            return new UsernamePasswordAuthenticationToken(authentication.getName(),
                    authentication.getCredentials(),
                    Set.of());
        });
        when(userRepository.findByUsername(any())).thenReturn(Optional.of(user));
        when(serverConfiguration.getAccessToken()).thenReturn(getAccessTokenConfig());
        when(serverConfiguration.getRefreshToken()).thenReturn(getRefreshTokenConfig());
        when(serverConfiguration.getIdToken()).thenReturn(getIdTokenConfig());
        when(accessTokenService.createToken(any())).thenReturn(AccessTokenDto.builder().token("token").build());
        when(refreshTokenService.createToken(any())).thenReturn(RefreshTokenDto.builder().token("token").build());
        when(idTokenService.createToken(any())).thenReturn(IdTokenDto.builder().token("token").build());

        TokenResponseDto tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);

        assertThat(tokenResponse.getAccessToken())
                .isNotNull();

        assertThat(tokenResponse.getIdToken())
                .isNotNull();

        assertThat(tokenResponse.getRefreshToken())
                .isNotNull();

        assertThat(tokenResponse.getExpiresIn())
                .isNotNull();

        verify(clientRepository, times(1)).findByClientId(any());
        verify(clientAuthenticationProvider, times(1)).authenticate(any());
        verify(userAuthenticationProvider, times(1)).authenticate(any());
        verify(userRepository, times(1)).findByUsername(any());
        verify(serverConfiguration, times(1)).getAccessToken();
        verify(serverConfiguration, times(1)).getRefreshToken();
        verify(serverConfiguration, times(1)).getIdToken();
        verify(accessTokenService, times(1)).createToken(any());
        verify(refreshTokenService, times(1)).createToken(any());
        verify(idTokenService, times(1)).createToken(any());
    }

    @DisplayName("Unmatched Basic Credentials and Params Credentials Throws Exception")
    @Test
    void unmatchedBasicCredentialsAndParamsCredentialsThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            tokenRequest.setClientSecret("invalidSecret");
            tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Invalid Client Id Throws Exception")
    @Test
    void invalidClientIdThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Public Client Tries Request Throws Exception")
    @Test
    void publicClientTriesRequestThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            client.setConfidential(false);
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
            tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_PASSWORD.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }

            verify(clientRepository, times(1)).findByClientId(any());
        }
    }

    @DisplayName("Insufficient Client Throws Exception")
    @Test
    void insufficientClientThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            client.setGrantTypes(Set.of());
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
            tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidGrantException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_PASSWORD.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }

            verify(clientRepository, times(1)).findByClientId(any());
        }
    }

    @DisplayName("Invalid User Id Exception")
    @Test
    void invalidUserIDThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
            tokenResponse = passwordTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (BadCredentialsException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
        } finally {
            if(tokenResponse != null) {
                fail("Catch block didn't work");
            }

            verify(clientRepository, times(1)).findByClientId(any());
        }
    }

}