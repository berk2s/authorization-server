package com.berk2s.authorizationserver.web.controllers.oauth;

import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ClientCredentialsTokenTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    String encodedAuthorization;

    @BeforeEach
    void setUp() {
        params.add("client_id", "clientWithSecret");
        params.add("client_secret", "clientSecret");
        params.add("scope", "");
        params.add("grant_type", "client_credentials");

        encodedAuthorization = AuthenticationParser.encodeBase64("clientWithSecret", "clientSecret");
    }

    @DisplayName("Client Credentials Token Request Returns Successfully")
    @Test
    void testClientCredentialsTokenRequestReturnsSuccessfully() throws Exception {

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.refresh_token", hasLength(48)))
                .andExpect(jsonPath("$.access_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                .andExpect(jsonPath("$.token_type", is(TokenType.BEARER.name())))
                .andExpect(jsonPath("$.expires_in").isNumber());
    }

    @DisplayName("Unmatched Basic Credentials and Params Credentials")
    @Test
    void testUnmatchedBasicCredentialsAndParamsCredentials() throws Exception {

        String invalidEncodedAuthorization = AuthenticationParser.encodeBase64("clientWithSecret", "invalidClientSecret");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .header("Authorization", invalidEncodedAuthorization)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT.getDesc())));
    }

    @DisplayName("Invalid Client Id")
    @Test
    void testInvalidClientId() throws Exception {

        params.set("client_id", "invalidClientId");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT.getDesc())));
    }

    @DisplayName("Public Client Tries Request")
    @Test
    void testPublicClientTriesRequest() throws Exception {

        params.set("client_id", "clientId");
        params.set("client_secret", "");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc())));
    }

    @DisplayName("Insufficient Client Grant Type")
    @Test
    void testInsufficientClientGrantType() throws Exception {

        params.set("client_id", "clientWithoutClientCredentials");
        params.set("client_secret", "clientSecret");

        mockMvc.perform(post(TokenController.ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .params(params))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is(ErrorType.INVALID_GRANT.getError())))
                .andExpect(jsonPath("$.error_description", is(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CLIENT_CREDENTIALS.getDesc())));
    }
}
