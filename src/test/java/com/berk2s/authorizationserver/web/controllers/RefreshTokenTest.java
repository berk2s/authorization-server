package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

import java.time.Duration;
import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class RefreshTokenTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    ServerConfiguration serverConfiguration;

    LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    String encodedAuthorization;

    @BeforeEach
    void setUp() {

        Duration refreshTokenDuration = serverConfiguration.getRefreshToken().getLifetime();

        RefreshTokenDto refreshToken = refreshTokenService
                .createToken(TokenCommand.builder()
                        .userDetails(new SecurityUserDetails(getUser()))
                        .clientId("clientId")
                        .scopes(Set.of("openid"))
                        .duration(refreshTokenDuration)
                        .build());

        params.add("client_id", "clientId");
        params.add("client_secret", "");
        params.add("scope", "openid");
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken.getToken());

        encodedAuthorization = AuthenticationParser.encodeBase64("clientWithSecret", "clientSecret");
    }

    @DisplayName("Refresh Token Returns Successfully")
    @Test
    void refreshTokenReturnsSuccessfully() throws Exception {

        mockMvc.perform(post(TokenController.ENDPOINT)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                .andExpect(status().is2xxSuccessful())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.refresh_token", hasLength(48)))
                .andExpect(jsonPath("$.access_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                .andExpect(jsonPath("$.id_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                .andExpect(jsonPath("$.token_type", is(TokenType.BEARER.name())))
                .andExpect(jsonPath("$.expires_in").isNumber());
    }

    @DisplayName("Invalid Client Id")
    @Test
    void testInvalidClientId() throws Exception {

        params.set("client_id", "invalidClientId");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT.getDesc())));
    }

    @DisplayName("Insufficient Client Grant")
    @Test
    void insufficientClientGrant() throws Exception {

        params.set("client_id", "clientWithoutRefreshToken");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_GRANT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_REFRESH_TOKEN.getDesc())));
    }

}
