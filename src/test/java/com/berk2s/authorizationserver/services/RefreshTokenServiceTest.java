package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.services.impl.RefreshTokenServiceImpl;
import com.berk2s.authorizationserver.web.mappers.TokenMapper;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenConfigServiceTest {

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Spy
    private final TokenMapper tokenMapper = Mappers.getMapper(TokenMapper.class);

    @InjectMocks
    RefreshTokenServiceImpl refreshTokenService;

    TokenCommand tokenCommand;
    User user;
    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("username");

        tokenCommand = TokenCommand.builder()
                .user(user)
                .clientId("clientId")
                .scopes(Set.of("scope", "openid"))
                .duration(Duration.ofHours(1))
                .build();
    }

    @DisplayName("Should Refresh Token Returns Successfully")
    @Test
    void shouldRefreshTokenReturnsSuccessfully() {

        RefreshTokenDto refreshToken = refreshTokenService.createToken(tokenCommand);

        assertThat(refreshToken.getToken().length())
                .isEqualTo(48);

    }
}