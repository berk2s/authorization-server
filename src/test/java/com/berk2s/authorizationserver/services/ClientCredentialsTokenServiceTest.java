package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.ClientCredentialsTokenServiceImpl;
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
class ClientCredentialsTokenServiceTest extends TokenServiceTest {

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @Mock
    ClientRepository clientRepository;

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    ServerConfiguration serverConfiguration;

    @InjectMocks
    ClientCredentialsTokenServiceImpl clientCredentialsTokenService;

    TokenRequestDto tokenRequest;
    String encodedAuthorization;
    Client client;
    UUID id;

    @BeforeEach
    void setUp() {
        tokenRequest = TokenRequestDto.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .grantType("client_credentials")
                .scope("")
                .build();

        id = UUID.randomUUID();

        client = new Client();
        client.setId(id);
        client.setClientId("clientId");
        client.setClientSecret("clientSecret");
        client.setConfidential(true);
        client.setGrantTypes(Set.of(GrantType.CLIENT_CREDENTIALS));

        encodedAuthorization = AuthenticationParser.encodeBase64("clientId", "clientSecret");

    }

    @DisplayName("Should Client Credentials Token Returns Successfully With Basic Header")
    @Test
    void shouldClientCredentialsTokenReturnsSuccessfully() {
        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
        when(clientAuthenticationProvider.authenticate(any())).thenAnswer(i -> {
            Authentication authentication = (Authentication) i.getArguments()[0];
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials().toString(), Set.of());
        });
        when(refreshTokenService.createToken(any())).thenReturn(RefreshTokenDto.builder().token("token").build());
        when(accessTokenService.createToken(any())).thenReturn(AccessTokenDto.builder().token("token").build());
        when(serverConfiguration.getAccessToken()).thenReturn(getAccessTokenConfig());
        when(serverConfiguration.getRefreshToken()).thenReturn(getRefreshTokenConfig());

        TokenResponseDto tokenResponse = clientCredentialsTokenService.getToken(encodedAuthorization, tokenRequest);

        assertThat(tokenResponse.getTokenType())
                .isEqualTo(TokenType.BEARER.name());

        assertThat(tokenResponse.getAccessToken())
                .isNotNull();

        assertThat(tokenResponse.getRefreshToken())
                .isNotNull();

        assertThat(tokenResponse.getExpiresIn())
                .isNotNull();

        verify(clientRepository, times(1)).findByClientId(any());
        verify(clientAuthenticationProvider, times(1)).authenticate(any());
        verify(accessTokenService, times(1)).createToken(any());
        verify(refreshTokenService, times(1)).createToken(any());
        verify(serverConfiguration, times(1)).getAccessToken();
        verify(serverConfiguration, times(1)).getRefreshToken();
    }

    @DisplayName("Unmatched Basic Credentials And Param Credentials Throws Exception")
    @Test
    void shouldBasicClientCredentialsAndParamCredentialsThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            tokenResponse = clientCredentialsTokenService.getToken(encodedAuthorization, TokenRequestDto.builder()
                                                .clientId("invalidClientId")
                                                .clientSecret("invalidClientSecret")
                                                .build());
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if (tokenResponse != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Invalid Client Id Throws Exception")
    @Test
    void shouldInvalidClientIdThrowsException() {
        TokenResponseDto tokenResponse = null;
        try {
            tokenResponse = clientCredentialsTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if (tokenResponse != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Public Client Tries Request Throws Exception")
    @Test
    void shouldPublicClientTriesRequestThrowsException() {
        TokenResponseDto tokenResponse = null;
        client.setConfidential(false);
        try {
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
            tokenResponse = clientCredentialsTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc());
        } finally {
            if (tokenResponse != null) {
                fail("Catch block didn't work");
            }

            verify(clientRepository, times(1)).findByClientId(any());
        }
    }

    @DisplayName("Insufficient Client Tries Request Throws Exception")
    @Test
    void insufficientClientTriesRequestThrowsException() {
        TokenResponseDto tokenResponse = null;
        client.setGrantTypes(Set.of());
        try {
            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
            tokenResponse = clientCredentialsTokenService.getToken(encodedAuthorization, tokenRequest);
        } catch (InvalidGrantException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc());
        } finally {
            if (tokenResponse != null) {
                fail("Catch block didn't work");
            }

            verify(clientRepository, times(1)).findByClientId(any());
        }
    }

}