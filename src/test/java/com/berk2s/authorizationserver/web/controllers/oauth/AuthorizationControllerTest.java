package com.berk2s.authorizationserver.web.controllers.oauth;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import static org.hamcrest.Matchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthorizationControllerTest {

    @Autowired
    MockMvc mockMvc;

    SecurityUserDetails securityUserDetails;
    User user;

    LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("username");
        user.setPassword("password");

        securityUserDetails = new SecurityUserDetails(user);

        params.add("response_type", "code");
        params.add("scope", "openid");
        params.add("client_id", "clientId");
        params.add("redirect_uri", "http://redirect-uri");
        params.add("code_challenge", "12345");
        params.add("state", "12345");
        params.add("code_challenge_method", "SHA256");
    }

    @DisplayName("Test Endpoint Returns Successfully")
    @Test
    void endpointsReturnsSuccessfully() throws Exception {

        mockMvc.perform(get(AuthorizationController.ENDPOINT)
                .with(user(securityUserDetails))
                .contentType(MediaType.APPLICATION_JSON)
                .queryParams(params))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("http://redirect-uri?code=**&state=**"));
    }

    @DisplayName("Test Authorization Errors")
    @Nested
    class TestAuthorizationErrors {

        @DisplayName("Invalid Security User Details Returns Error")
        @WithMockUser(username = "mockuser")
        @Test
        void invalidSecurityUserDetailsReturnsError() throws Exception {
            mockMvc.perform(get(AuthorizationController.ENDPOINT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .queryParams(params))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_GRANT.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.BAD_CREDENTIALS.getDesc())));
        }

        @DisplayName("Invalid Client Id Returns Error")
        @Test
        void invalidClientIdReturnsError() throws Exception {
            params.remove("client_id");
            params.add("client_id", "invalidClientId");

            mockMvc.perform(get(AuthorizationController.ENDPOINT)
                    .with(user(securityUserDetails))
                    .contentType(MediaType.APPLICATION_JSON)
                    .queryParams(params))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT.getDesc())));
        }

        @DisplayName("Unmatched Redirect Uri Returns Error")
        @Test
        void unmatchedRedirectUriReturnsError() throws Exception {
            params.remove("redirect_uri");
            params.add("redirect_uri", "http://invalid-redirect-uri");

            mockMvc.perform(get(AuthorizationController.ENDPOINT)
                    .with(user(securityUserDetails))
                    .contentType(MediaType.APPLICATION_JSON)
                    .queryParams(params))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_REDIRECT_URI.getDesc())));
        }


        @DisplayName("Missing PKCE Returns Error")
        @Test
        void missingPKCEReturnsError() throws Exception {
            params.remove("code_challenge");
            params.remove("code_challenge_method");

            mockMvc.perform(get(AuthorizationController.ENDPOINT)
                    .with(user(securityUserDetails))
                    .contentType(MediaType.APPLICATION_JSON)
                    .queryParams(params))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("http://redirect-uri"
                            + "?error=" + ErrorType.INVALID_REQUEST.getError()
                            + "&error_description=" + URLEncoder.encode(ErrorDesc.INVALID_CLIENT_TYPE.getDesc(), StandardCharsets.UTF_8)
                            + "&state=" + params.get("state").get(0)));
        }

        @DisplayName("Unmatched Client Grant Type Returns Error")
        @Test
        void unmatchedClientGrantTypeReturnsError() throws Exception {
            params.remove("client_id");
            params.add("client_id", "clientWithoutCode");

            mockMvc.perform(get(AuthorizationController.ENDPOINT)
                    .with(user(securityUserDetails))
                    .contentType(MediaType.APPLICATION_JSON)
                    .queryParams(params))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("http://redirect-uri"
                            + "?error=" + ErrorType.INVALID_GRANT.getError()
                            + "&error_description=" + URLEncoder.encode(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc(), StandardCharsets.UTF_8)
                            + "&state=" + params.get("state").get(0)));
        }


    }
}
