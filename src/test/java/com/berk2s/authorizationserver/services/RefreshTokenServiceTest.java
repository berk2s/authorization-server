package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.impl.RefreshTokenServiceImpl;
import com.berk2s.authorizationserver.web.exceptions.TokenNotFoundException;
import com.berk2s.authorizationserver.web.mappers.TokenMapper;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Spy
    private final TokenMapper tokenMapper = Mappers.getMapper(TokenMapper.class);

    @InjectMocks
    RefreshTokenServiceImpl refreshTokenService;

    TokenCommand tokenCommand;
    RefreshToken refreshToken;
    RefreshTokenDto refreshTokenDto;
    User user;
    UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");

        SecurityUserDetails securityUserDetails = new SecurityUserDetails(user);

        tokenCommand = TokenCommand.builder()
                .userDetails(securityUserDetails)
                .clientId("clientId")
                .scopes(Set.of("scope", "openid"))
                .duration(Duration.ofHours(1))
                .build();

        refreshToken = RefreshToken.builder()
                .token(RandomStringUtils.random(48, true, true))
                .id(1L)
                .expiryDateTime(LocalDateTime.now().plusMinutes(10))
                .notBefore(LocalDateTime.now())
                .issueTime(LocalDateTime.now())
                .subject(userId)
                .build();

        refreshTokenDto = tokenMapper.refreshTokenToRefreshTokenDto(refreshToken);
    }

    @DisplayName("Should Refresh Token Returns Successfully")
    @Test
    void shouldRefreshTokenReturnsSuccessfully() {

        when(refreshTokenRepository.save(any())).thenAnswer(i -> i.getArguments()[0]);

        RefreshTokenDto refreshToken = refreshTokenService.createToken(tokenCommand);

        assertThat(refreshToken.getToken().length())
                .isEqualTo(48);

        assertThat(refreshToken.getSubject())
                .isEqualTo(userId.toString());

        verify(refreshTokenRepository, times(1)).save(any());

    }

    @DisplayName("Should Get Refresh Token Successfully")
    @Test
    void shouldGetRefreshTokenSuccessfully() {
        when(refreshTokenRepository.findByToken(any())).thenReturn(Optional.of(refreshToken));

        RefreshTokenDto returnedRefreshToken = refreshTokenService.getToken(refreshToken.getToken());

        assertThat(returnedRefreshToken)
                .isEqualTo(refreshTokenDto);

        verify(refreshTokenRepository, times(1)).findByToken(any());
    }


    @DisplayName("Should Invalid Refresh Token Throws Exception")
    @Test
    void shouldInvalidRefreshTokenThrowsException() {
        RefreshTokenDto returnedRefreshToken = null;

        try {
            returnedRefreshToken = refreshTokenService.getToken(refreshToken.getToken());
        } catch (TokenNotFoundException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_TOKEN.getDesc());
        } finally {
            if (returnedRefreshToken != null) {
                fail("Catch block didn't work");
            }
        }
    }


    @DisplayName("Should Get Refresh Token Successfully")
    @Test
    void shouldDeleteTokenSuccessfully() {

        doNothing().when(refreshTokenRepository).deleteByToken(any());

        refreshTokenService.deleteToken(refreshToken.getToken());

        verify(refreshTokenRepository, times(1)).deleteByToken(any());
    }

}