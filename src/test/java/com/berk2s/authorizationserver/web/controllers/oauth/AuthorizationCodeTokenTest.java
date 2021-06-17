package com.berk2s.authorizationserver.web.controllers.oauth;

import com.berk2s.authorizationserver.services.AuthorizationCodeService;
import com.berk2s.authorizationserver.services.PKCEService;
import com.berk2s.authorizationserver.utils.AuthorizationParser;
import com.berk2s.authorizationserver.utils.ChallengeMethod;
import com.berk2s.authorizationserver.web.IntegrationTest;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.hamcrest.Matchers.*;

public class TokenControllerTest extends IntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AuthorizationCodeService authorizationCodeService;

    @Autowired
    PKCEService pkceService;

    @DisplayName("Test Authorization Code Token")
    @Nested
    class TestAuthorizationCodeToken {

        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        String encodedAuthorization;

        @BeforeEach
        void setUp() throws URISyntaxException {
            params.add("client_id", "clientWithSecret");
            params.add("client_secret", "clientSecret");
            params.add("scope", "openid");
            params.add("grant_type", "authorization_code");

            encodedAuthorization = AuthorizationParser.encodeBase64("clientWithSecret", "clientSecret");

        }

        @DisplayName("Test Authorization Code Token Request Without PKCE")
        @Test
        void testAuthorizationCodeTokenRequestWithoutPKCE() throws Exception {

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientWithSecret",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    "",
                    "plain");

            params.add("code", authorizationCodeDto.getCode());

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(jsonPath("$.refresh_token", hasLength(48)))
                    .andExpect(jsonPath("$.access_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                    .andExpect(jsonPath("$.id_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                    .andExpect(jsonPath("$.token_type", is(TokenType.BEARER.name())))
                    .andExpect(jsonPath("$.expires_in").isNumber());

        }

        @DisplayName("Test Authorization Code Token Request Error Without PKCE By Public Client ")
        @Test
        void testAuthorizationCodeTokenRequestErrorWithoutPKCEByPublicClient() throws Exception {

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    "",
                    "plain");
            params.remove("code");
            params.remove("client_id");
            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());

            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT_TYPE.getDesc())));
        }

        @DisplayName("Test Authorization Code Token Request With PKCE By Public Client")
        @Test
        void testAuthorizationCodeTokenRequestWithPKCEByPublicClient() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    ChallengeMethod.S256.name());

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());
            params.add("code_verifier", codeVerifier);

            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(jsonPath("$.refresh_token", hasLength(48)))
                    .andExpect(jsonPath("$.access_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                    .andExpect(jsonPath("$.id_token", matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$")))
                    .andExpect(jsonPath("$.token_type", is(TokenType.BEARER.name())))
                    .andExpect(jsonPath("$.expires_in").isNumber());

        }

        @DisplayName("Test Authorization Code Token With Invalid Client Credentials")
        @Test
        void testAuthorizationCodeTokenRequestWithInvalidClientCredentials() throws Exception {

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", "invalid credentials")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_GRANT.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.BAD_CREDENTIALS.getDesc())));

        }

        @DisplayName("Test Authorization Code Token With Invalid Client")
        @Test
        void testAuthorizationCodeTokenRequestWithInvalidClient() throws Exception {

            LinkedMultiValueMap<String, String> params2 = new LinkedMultiValueMap<>();
            params2.add("client_id", "invalidClient");
            params2.add("client_secret", "clientSecret");
            params2.add("scope", "openid");
            params2.add("grant_type", "authorization_code");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params2))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_CLIENT.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CLIENT.getDesc())));

        }

        @DisplayName("Test Authorization Code Token With Missing Grant Type")
        @Test
        void testAuthorizationCodeTokenRequestWithMissingGrantType() throws Exception {
            params.set("client_id", "clientWithoutCode");
            encodedAuthorization = AuthorizationParser.encodeBase64("clientWithoutCode", "clientSecret");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_GRANT.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc())));

        }

        @DisplayName("Test Invalid Authorization Code")
        @Test
        void testInvalidAuthorizationCode() throws Exception {

            params.remove("code");
            params.add("code", "codoeodoe");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.NULL_CODE.getDesc())));

        }

        @DisplayName("Test Missing Code Verifier")
        @Test
        void testMissingCodeVerifier() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    ChallengeMethod.S256.name());

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());

            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.MISSING_CODE_VERIFIER.getDesc())));

        }

        @DisplayName("Test Invalid Code Verifier")
        @Test
        void testInvalidCodeVerifier() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    ChallengeMethod.S256.name());

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());
            params.add("code_verifier", "invalid_code_verifier");
            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CODE_VERIFIER.getDesc())));

        }

        @DisplayName("Test Unmatched Code Challenge and Code Verifier When Type is SHA256")
        @Test
        void testUnmatchedCodeChallengeAndCodeVerifierWhenTypeIsSHA256() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    ChallengeMethod.S256.name());

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());
            params.add("code_verifier", RandomStringUtils.random(64, true, true));
            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc())));

        }

        @DisplayName("Test Unmatched Code Challenge and Code Verifier When Type is Plain")
        @Test
        void testUnmatchedCodeChallengeAndCodeVerifierWhenTypeIsPlain() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    ChallengeMethod.PLAIN.name());

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());
            params.add("code_verifier", RandomStringUtils.random(64, true, true));
            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc())));

        }

        @DisplayName("Test Unknown Challenge Method")
        @Test
        void testUnknownChallengeMethod() throws Exception {

            String codeVerifier = RandomStringUtils.random(64, true, true);
            String codeChallenge = pkceService.hashCodeVerifier(codeVerifier);

            AuthorizationCodeDto authorizationCodeDto = authorizationCodeService.createAuthorizationCode("clientId",
                    new URI("http://redirect-uri"),
                    Set.of("openid"),
                    getUser().getId().toString(),
                    "nonce",
                    codeChallenge,
                    "unknown_method");

            params.remove("code");
            params.remove("client_id");
            params.remove("client_secret");

            params.add("client_id", "clientId");
            params.add("code", authorizationCodeDto.getCode());
            params.add("code_verifier", RandomStringUtils.random(64, true, true));
            encodedAuthorization = AuthorizationParser.encodeBase64("clientId", "");

            mockMvc.perform(post(TokenController.ENDPOINT)
                    .header("Authorization", encodedAuthorization)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .params(params))
                    .andExpect(status().is4xxClientError())
                    .andExpect(jsonPath("$.error", is(ErrorType.INVALID_REQUEST.getError())))
                    .andExpect(jsonPath("$.error_description", is(ErrorDesc.INVALID_CHALLENGE_METHOD.getDesc())));

        }

    }

}
