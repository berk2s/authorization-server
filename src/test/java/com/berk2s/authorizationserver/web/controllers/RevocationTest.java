package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.IdTokenService;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.IdTokenDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

import java.time.Duration;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class RevocationTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ServerConfiguration serverConfiguration;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    AccessTokenService accessTokenService;

    @Autowired
    IdTokenService idTokenService;

    LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    String encodedAuthorization;

    RefreshTokenDto refreshToken;
    AccessTokenDto accessTokenDto;
    IdTokenDto idTokenDto;
    User user;

    @BeforeEach
    void setUp() {
        user = getUser();

        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();
        Duration accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();
        Duration idTokenDuration = serverConfiguration.getIdToken().getLifetime();

        refreshToken = refreshTokenService
                .createToken(TokenCommand.builder()
                        .userDetails(new SecurityClientDetails(getClient()))
                        .clientId("clientId")
                        .scopes(Set.of("openid"))
                        .duration(refreshTokenDuration)
                        .build());

        accessTokenDto = accessTokenService.createToken(TokenCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .clientId("clientId")
                .scopes(Set.of("openid", "profile"))
                .nonce("nonce")
                .duration(accessTokenDuration)
                .build());

        idTokenDto = idTokenService.createToken(TokenCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .clientId("clientId")
                .scopes(Set.of("openid"))
                .nonce("nonce")
                .duration(idTokenDuration)
                .build());

        params.add("token", refreshToken.getToken());

        encodedAuthorization = AuthenticationParser.encodeBase64("clientWithSecret", "clientSecret");
    }


    @DisplayName("Revoke Refresh Token Successfully")
    @Test
    void revokeRefreshTokenSuccessfully() throws Exception {
        mockMvc.perform(post(RevocationController.ENDPOINT)
                .header("Authorization", encodedAuthorization)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().is2xxSuccessful());
    }


}
