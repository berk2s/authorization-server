package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.controllers.UserInfoController;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class UserInfoTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccessTokenService accessTokenService;

    @Autowired
    ServerConfiguration serverConfiguration;

    User user;

    String bearerToken;

    @BeforeEach
    void setUp() {
        user = getUser();

        TokenCommand tokenCommand = TokenCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .nonce("nonce")
                .clientId("clientId")
                .scopes(Set.of("openid", "userinfo"))
                .duration(serverConfiguration.getAccessToken().getLifetime())
                .build();

        AccessTokenDto accessToken = accessTokenService.createToken(tokenCommand);

        bearerToken =  "Bearer " + accessToken.getToken();

    }

    @DisplayName("User Info Endpoint Returns Successfully")
    @Test
    void userInfoEndpointReturnsSuccessfully() throws Exception {
        mockMvc.perform(get(UserInfoController.ENDPOINT)
                .header("Authorization", bearerToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.sub", is(user.getId().toString())))
                .andExpect(jsonPath("$.name", is(user.getFirstName() + " " + user.getLastName())))
                .andExpect(jsonPath("$.nickname", is(user.getUsername())))
                .andExpect(jsonPath("$.profile", is(user.getUsername())))
                .andExpect(jsonPath("$.roles.length()", is(user.getRoles().size())))
                .andExpect(jsonPath("$.authorities.length()", is(user.getAuthorities().size())))
                .andExpect(jsonPath("$.given_name", is(user.getFirstName())))
                .andExpect(jsonPath("$.family_name", is(user.getLastName())))
                .andExpect(jsonPath("$.preferred_username", is(user.getUsername())));
    }

}
