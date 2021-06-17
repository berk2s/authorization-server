package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.anyOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceImplTest {

    @Mock
    JWTService jwtService;

    @InjectMocks
    AccessTokenServiceImpl accessTokenService;

    TokenCommand tokenCommand;
    User user;
    UUID userId;


    @BeforeEach
    void setUp() throws JOSEException {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");

        SecurityUserDetails securityUserDetails = new SecurityUserDetails(user);

        tokenCommand = TokenCommand.builder()
                .securityUserDetails(securityUserDetails)
                .clientId("clientId")
                .scopes(Set.of("scope", "openid"))
                .nonce("nonce")
                .duration(Duration.ofHours(1))
                .build();
    }

    @DisplayName("Should Access Token Returns Successfully")
    @Test
    void testShouldAccessTokenReturnsSuccessfully() {
        when(jwtService.createJWT(any())).thenReturn("token");

        AccessTokenDto accessTokenDto = accessTokenService.createToken(tokenCommand);

        assertThat(accessTokenDto.getToken())
                .isNotNull();

        verify(jwtService, times(1)).createJWT(any());
    }


}