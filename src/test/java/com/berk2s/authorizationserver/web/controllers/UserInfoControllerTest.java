package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.domain.user.Role;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.IdTokenService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

public class UserInfoControllerTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ServerConfiguration serverConfiguration;

    @Autowired
    AccessTokenService accessTokenService;

    AccessTokenDto accessTokenDto;
    User user;
    String authorizationHeader;
    Duration accessTokenDuration;

    @BeforeEach
    void setUp() {
        user = getUser();

        accessTokenDuration = serverConfiguration.getAccessToken().getLifetime();

        accessTokenDto = accessTokenService.createToken(TokenCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .clientId("clientId")
                .scopes(Set.of("openid", "offline_access"))
                .nonce("nonce")
                .duration(accessTokenDuration)
                .build());

        authorizationHeader = "Bearer " + accessTokenDto.getToken();
    }

    @DisplayName("User Info Endpoint Returns Successfully")
    @Test
    void userinfoEndpointReturnsSuccessfully() throws Exception {

        List<String> roles = user.getRoles().stream().map(Role::getRoleName).collect(Collectors.toList());
        List<String> authorities = user.getAuthorities().stream().map(Authority::getAuthorityName).collect(Collectors.toList());

        mockMvc.perform(get(UserInfoController.ENDPOINT)
                .header("Authorization", authorizationHeader))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.sub", is(user.getId().toString())))
                .andExpect(jsonPath("$.name", is(user.getFirstName() + " " + user.getLastName())))
                .andExpect(jsonPath("$.nickname", is(user.getUsername())))
                .andExpect(jsonPath("$.profile", is(user.getUsername())))
                .andExpect(jsonPath("$.first_name", is(user.getFirstName())))
                .andExpect(jsonPath("$.last_name", is(user.getLastName())))
                .andExpect(jsonPath("$.preferred_username", is(user.getUsername())))
                .andExpect(jsonPath("$.email", is(user.getEmail())))
                .andExpect(jsonPath("$.email_verified", is(user.isEmailVerified())))
                .andExpect(jsonPath("$.phone_number", is(user.getPhoneNumber())))
                .andExpect(jsonPath("$.phone_number_verified", is(user.isPhoneNumberVerified())))
                .andExpect(jsonPath("$.roles", hasItem(roles.get(0))))
                .andExpect(jsonPath("$.roles", hasItem(roles.get(1))))
                .andExpect(jsonPath("$.authorities", hasItem(authorities.get(0))));
    }

    @DisplayName("User Info Endpoint Returns Unauthorized")
    @Test
    void userinfoEndpointReturnsUnauthorized() throws Exception {

        accessTokenDto = accessTokenService.createToken(TokenCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .clientId("clientId")
                .scopes(Set.of("openid"))
                .nonce("nonce")
                .duration(accessTokenDuration)
                .build());

        authorizationHeader = "Bearer " + accessTokenDto.getToken();

        mockMvc.perform(get(UserInfoController.ENDPOINT)
                .header("Authorization", authorizationHeader))
                .andExpect(status().isForbidden());

    }

}
