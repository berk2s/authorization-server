package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.UserType;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.IntrospectionServiceImpl;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.mappers.TokenMapper;
import com.berk2s.authorizationserver.web.models.IntrospectionRequestDto;
import com.berk2s.authorizationserver.web.models.IntrospectionResponseDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mapstruct.factory.Mappers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IntrospectionServiceTest {

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    JWTService jwtService;

    @Mock
    UserRepository userRepository;

    @Mock
    ClientRepository clientRepository;

    TokenMapper tokenMapper = Mappers.getMapper(TokenMapper.class);

    @InjectMocks
    IntrospectionServiceImpl introspectionService;

    Client client;
    RefreshToken refreshToken;
    RefreshTokenDto refreshTokenDto;
    User user;
    UUID clientId;
    UUID userId;

    String encodedAuthorization;

    IntrospectionRequestDto introspectionRequestDto;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");

        introspectionRequestDto = IntrospectionRequestDto.builder()
                .token("token")
                .build();

        clientId = UUID.randomUUID();

        client = new Client();
        client.setId(clientId);
        client.setClientId("clientId");
        client.setClientSecret("clientSecret");
        client.setConfidential(true);
        client.setGrantTypes(Set.of(GrantType.CLIENT_CREDENTIALS));

        refreshToken = RefreshToken.builder()
                .token(RandomStringUtils.random(48, true, true))
                .id(1L)
                .expiryDateTime(LocalDateTime.now().plusMinutes(10))
                .notBefore(LocalDateTime.now())
                .issueTime(LocalDateTime.now())
                .userType(UserType.CLIENT)
                .subject(userId)
                .clientId("clientId")
                .build();

        refreshTokenDto = tokenMapper.refreshTokenToRefreshTokenDto(refreshToken);

        encodedAuthorization = AuthenticationParser.encodeBase64("clientId", "clientSecret");

    }

    @DisplayName("Introspection Refresh Token Successfully")
    @Test
    void testIntrospectionRefreshTokenSuccessfully() {

        when(clientAuthenticationProvider.authenticate(any())).thenAnswer(a -> {
            Authentication authentication = (Authentication) a.getArguments()[0];

            return new UsernamePasswordAuthenticationToken(authentication.getName(),
                    authentication.getCredentials(),
                    Set.of());
        });

        when(refreshTokenService.getToken(any())).thenReturn(refreshTokenDto);

        when(clientRepository.findById(any())).thenReturn(Optional.of(client));

        IntrospectionResponseDto introspectionResponse =
                introspectionService.getTokenInfo(encodedAuthorization, introspectionRequestDto);

        assertThat(introspectionResponse.getClientId())
                .isEqualTo(client.getClientId());

        assertThat(introspectionResponse.isActive())
                .isEqualTo(true);

        assertThat(introspectionResponse.getScope())
                .isNotNull();

        assertThat(introspectionResponse.getUsername())
                .isNotNull();

        assertThat(introspectionResponse.getExp())
                .isNotNull();


        verify(clientRepository, times(1)).findById(any());
        verify(refreshTokenService, times(1)).getToken(any());
        verify(clientAuthenticationProvider, times(1)).authenticate(any());

    }

}