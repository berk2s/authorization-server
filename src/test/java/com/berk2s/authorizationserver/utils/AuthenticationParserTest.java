package com.berk2s.authorizationserver.utils;

import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.TokenRequestDto;
import com.berk2s.authorizationserver.web.models.token.TokenResponseDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;


class AuthenticationParserTest {

    @DisplayName("Test Basic Client Credentials")
    @Test
    void testBasicClientCredentials() {
        String encodedCredentials = AuthenticationParser.encodeBase64("clientId", "clientSecret");

        String authorizationHeader = encodedCredentials;

        ClientCredentialsDto parsedHeader = AuthenticationParser.basicParser(authorizationHeader);

        assertThat(parsedHeader.getClientId())
                .isEqualTo("clientId");

        assertThat(parsedHeader.getClientSecret())
                .isEqualTo("clientSecret");
    }

    @DisplayName("Test Invalid Basic Client Credentials")
    @Test
    void testInvalidBasicClientCredentials() {
        ClientCredentialsDto parsedHeader = null;

        try {
            parsedHeader = AuthenticationParser.basicParser("invalid_header");
        } catch (BadCredentialsException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
        } finally {
            if(parsedHeader != null) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Test Basic Client Credentials And Token Request Credentials")
    @Test
    void testBasicClientCredentialsAndTokenRequestCredentials() {
        TokenRequestDto tokenRequest = TokenRequestDto.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .build();

        String encodedCredentials = AuthenticationParser.encodeBase64("clientId", "clientSecret");

        ClientCredentialsDto clientCredentials = AuthenticationParser.parseAndValidate(encodedCredentials, tokenRequest);

        assertThat(clientCredentials.getClientId())
                .isEqualTo(tokenRequest.getClientId());

        assertThat(clientCredentials.getClientSecret())
                .isEqualTo(tokenRequest.getClientSecret());

    }

    @DisplayName("Test Basic Client Credentials And Token Request Credentials Throws Exception")
    @Test
    void testBasicClientCredentialsAndTokenRequestCredentialsThrowsException() {
        ClientCredentialsDto clientCredentials = null;

        try {
            TokenRequestDto tokenRequest = TokenRequestDto.builder()
                    .clientId("invalidClientId")
                    .clientSecret("clientSecret")
                    .build();

            String encodedCredentials = AuthenticationParser.encodeBase64("clientId", "clientSecret");

            clientCredentials = AuthenticationParser.parseAndValidate(encodedCredentials, tokenRequest);
        } catch (InvalidClientException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if(clientCredentials != null) {
                fail("Catch block didn't work");
            }
        }

    }

}