package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.RevocationServiceImpl;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.models.RevocationRequestDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import org.apache.commons.lang3.RandomStringUtils;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RevocationServiceTest {

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Mock
    ClientRepository clientRepository;

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @InjectMocks
    RevocationServiceImpl revocationService;

    RevocationRequestDto revocationRequest;
    String encodedAuthorization;

    Client client;

    @BeforeEach
    void setUp() {

        client = Client.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .confidential(true)
                .build();

        revocationRequest = RevocationRequestDto.builder()
                .token(RandomStringUtils.random(48, true, true))
                .clientId("clientId")
                .clientSecret("clientSecret")
                .build();

        encodedAuthorization = AuthenticationParser.encodeBase64("clientId", "clientSecret");
    }

    @DisplayName("Should Revoke Refresh Token Successfully")
    @Test
    void shouldRevokeRefreshTokenSuccessfully() {
        when(refreshTokenService.getToken(any())).thenReturn(RefreshTokenDto.builder().id(1L).build());
        when(clientAuthenticationProvider.authenticate(any())).thenAnswer(a -> {
            Authentication authentication = (Authentication) a.getArguments()[0];

            return new UsernamePasswordAuthenticationToken(authentication.getName(),
                    authentication.getCredentials(),
                    Set.of());
        });
        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

        revocationService.revokeToken(encodedAuthorization, revocationRequest);

        verify(refreshTokenService, times(1)).getToken(any());
        verify(clientAuthenticationProvider, times(1)).authenticate(any());
        verify(refreshTokenRepository, times(1)).deleteById(any());
        verify(clientRepository, times(1)).findByClientId(any());
    }

}