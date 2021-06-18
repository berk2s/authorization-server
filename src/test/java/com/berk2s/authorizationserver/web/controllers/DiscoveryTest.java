package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.services.DiscoveryService;
import com.berk2s.authorizationserver.web.DiscoveryController;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.DiscoveryDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

public class DiscoveryTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    DiscoveryService discoveryService;
    DiscoveryDto discovery;

    @BeforeEach
    void setUp() {
        discovery = discoveryService.getDiscovery();
    }

    @DisplayName("Discovery Endpoint Returns Successfully")
    @Test
    void discoveryEndpointReturnsSuccessfully() throws Exception {

        mockMvc.perform(get(DiscoveryController.ENDPOINT))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.issuer", is(discovery.getIssuer())))
                .andExpect(jsonPath("$.authorization_endpoint", is(discovery.getAuthorizationEndpoint())))
                .andExpect(jsonPath("$.token_endpoint", is(discovery.getTokenEndpoint())))
                .andExpect(jsonPath("$.userinfo_endpoint", is(discovery.getUserinfoEndpoint())))
                .andExpect(jsonPath("$.jwks_uri", is(discovery.getJwksUri())))
                .andExpect(jsonPath("$.registration_endpoint", is(discovery.getRegistrationEndpoint())))
                .andExpect(jsonPath("$.introspection_endpoint", is(discovery.getIntrospectionEndpoint())))
                .andExpect(jsonPath("$.revocation_endpoint", is(discovery.getRevocationEndpoint())))
                .andExpect(jsonPath("$.device_authorization_endpoint", is(discovery.getDeviceAuthorizationEndpoint())))
                .andExpect(jsonPath("$.request_object_endpoint", is(discovery.getRequestObjectEndpoint())))
                .andExpect(jsonPath("$.scopes_supported", is(discovery.getScopesSupported())))
                .andExpect(jsonPath("$.response_types_supported", is(discovery.getResponseTypesSupported())))
                .andExpect(jsonPath("$.response_modes_supported", is(discovery.getResponseModesSupported())))
                .andExpect(jsonPath("$.grant_types_supported", is(discovery.getGrantTypesSupported())))
                .andExpect(jsonPath("$.acr_values_supported", is(discovery.getAcrValuesSupported())))
                .andExpect(jsonPath("$.subject_types_supported", is(discovery.getSubjectTypesSupported())))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported", is(discovery.getIdTokenSigningAlgValuesSupported())))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported", is(discovery.getTokenEndpointAuthMethodsSupported())))
                .andExpect(jsonPath("$.token_endpoint_auth_signing_alg_values_supported", is(discovery.getTokenEndpointAuthSigningAlgValuesSupported())))
                .andExpect(jsonPath("$.claims_supported", is(discovery.getClaimsSupported())))
                .andExpect(jsonPath("$.code_challenge_methods_supported", is(discovery.getCodeChallengeMethodsSupported())));

    }

}
