package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.web.IntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class JWKControllerTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @DisplayName("JWK Set Endpoint Returns Successfully")
    @Test
    void jwkSetEndpointReturnsSuccessfully() throws Exception {
        mockMvc.perform(get(JWKSetController.ENDPOINT))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys.length()", is(1)))
                .andExpect(jsonPath("$.keys.[0].kty", is("RSA")));

    }

}
