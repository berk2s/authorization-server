package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.impl.AuthorizationServiceImpl;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidRedirectUriException;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import com.berk2s.authorizationserver.web.models.AuthorizeRequestParamDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

    @Mock
    private ClientRepository clientRepository;

    @Mock
    private AuthorizationCodeService authorizationCodeService;

    @InjectMocks
    private AuthorizationServiceImpl authorizationService;

    AuthorizeRequestParamDto params;
    SecurityUserDetails securityUserDetails;
    Client client;

    String callbackURL = "http://redirect-uri.com/callback";

    @BeforeEach
    void setUp() throws URISyntaxException {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("username");

        securityUserDetails = new SecurityUserDetails(user);

        client = new Client();
        client.setId(UUID.randomUUID());
        client.setClientId("client-id");
        client.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE));
        client.setRedirectUris(Set.of(new URI(callbackURL)));
        client.setConfidential(false);

        params = new AuthorizeRequestParamDto();
        params.setClientId("clientId");
        params.setCodeChallenge("codeChallenge");
        params.setRedirectUri(new URI(callbackURL));
        params.setScope("openid");
        params.setNonce("nonce");
        params.setCodeChallengeMethod("codeChallengeMethod");
        params.setState("state");
    }

    @DisplayName("Should Authorize Request Returns Successfully")
    @Test
    void testShouldAuthorizeRequestSuccessfully() throws URISyntaxException {
        AuthorizationCodeDto authorizationCodeDto = AuthorizationCodeDto.builder()
                .code("1234")
                .build();

        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

        when(authorizationCodeService.createAuthorizationCode(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(authorizationCodeDto);

        URI uri = authorizationService.authorizeRequest(params, securityUserDetails);

        assertThat(uri.toString())
                .isEqualTo(callbackURL
                        + "?code=" + authorizationCodeDto.getCode()
                        + "&state=" + params.getState());

        verify(clientRepository, times(1)).findByClientId(any());
        verify(authorizationCodeService, times(1)).createAuthorizationCode(any(), any(), any(), any(), any(), any(), any());
    }

    @Nested
    @DisplayName("Test Exceptions")
    class TestExceptions {

        @DisplayName("Invalid Security User Details Should Throws Exception")
        @Test
        void testShouldInvalidUserDetailsThrowsException() {
            URI uri = null;
            try {
                uri = authorizationService.authorizeRequest(params, null);
            } catch (BadCredentialsException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
            } finally {
                if(uri != null) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Invalid Client Throws Exceptions")
        @Test
        void shouldShouldClientThrowsException() {
            URI uri = null;
            try {
                uri = authorizationService.authorizeRequest(params, securityUserDetails);
            } catch (InvalidClientException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
            } finally {
                if(uri != null) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Missing Grant Type Throws Redirect")
        @Test
        void shouldMissingGrantTypeThrowsRedirect() {
            client.setGrantTypes(Set.of());

            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

            URI uri = authorizationService.authorizeRequest(params, securityUserDetails);

            assertThat(uri.toString())
                    .isEqualTo(params.getRedirectUri()
                            + "?error=" + ErrorType.INVALID_GRANT
                            + "&error_description=" + URLEncoder.encode(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc(), StandardCharsets.UTF_8)
                            + "&state=" + params.getState());

            verify(clientRepository, times(1)).findByClientId(any());
        }

        @DisplayName("Invalid Redirect Uri Throws Exception")
        @Test
        void shouldInvalidRedirectUriThrowsException() {
            URI uri = null;
            try {
                when(clientRepository.findByClientId(any())).thenReturn(Optional.ofNullable(client));
                params.setRedirectUri(new URI("http://invalid-uri"));

                uri = authorizationService.authorizeRequest(params, securityUserDetails);
            } catch (InvalidRedirectUriException | URISyntaxException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_REDIRECT_URI.getDesc());
            } finally {
                if(uri != null) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Public Client Requests Without PKCE Throws Error Redirect")
        @Test
        void shouldPublicClientRequestWithoutPKCEThrowsErrorRedirect() {
            params.setCodeChallenge(null);
            when(clientRepository.findByClientId(any())).thenReturn(Optional.ofNullable(client));

            URI uri = authorizationService.authorizeRequest(params, securityUserDetails);

            assertThat(uri.toString())
                    .isEqualTo(params.getRedirectUri().toString()
                            + "?error=" + ErrorType.INVALID_REQUEST.getError()
                            + "&error_description=" + URLEncoder.encode(ErrorDesc.INVALID_CLIENT_TYPE.getDesc(), StandardCharsets.UTF_8)
                            + "&state=" + params.getState());

            verify(clientRepository, times(1)).findByClientId(any());
        }

    }

}