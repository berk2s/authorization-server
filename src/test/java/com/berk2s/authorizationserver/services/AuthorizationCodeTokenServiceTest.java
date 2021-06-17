package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.AuthorizationCodeTokenServiceImpl;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.exceptions.InvalidRequestException;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import com.berk2s.authorizationserver.web.models.token.*;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeTokenServiceTest extends TokenServiceTest {

    @Mock
    ClientRepository clientRepository;

    @Mock
    AuthorizationCodeService authorizationCodeService;

    @Mock
    ClientAuthenticationProvider clientAuthenticationProvider;

    @Mock
    PKCEService pkceService;

    @Mock
    ServerConfiguration serverConfiguration;

    @Mock
    UserRepository userRepository;

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    RefreshTokenService refreshTokenService;

    @Mock
    IdTokenService idTokenService;

    @InjectMocks
    AuthorizationCodeTokenServiceImpl authorizationCodeTokenService;

    Client client;

    TokenRequestDto tokenRequest;
    AuthorizationCodeDto authorizationCode;
    User user;

    String authorizationHeader;

    @BeforeEach
    void setUp() throws URISyntaxException {
        authorizationHeader = AuthenticationParser.encodeBase64("clientId", "clientSecret");

        client = Client.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .grantTypes(Set.of(GrantType.PASSWORD,
                        GrantType.AUTHORIZATION_CODE,
                        GrantType.REFRESH_TOKEN, GrantType.TOKEN_EXCHANGE,
                        GrantType.CLIENT_CREDENTIALS))
                .redirectUris(Set.of(new URI("http://redirect-uri")))
                .confidential(true)
                .build();

        tokenRequest = TokenRequestDto.builder()
                .clientId(client.getClientId())
                .clientSecret("clientSecret")
                .code("code")
                .redirectUri(new URI("http://redirect-uri"))
                .codeVerifier("codeVerifier")
                .build();

        UUID subId = UUID.randomUUID();

        authorizationCode = AuthorizationCodeDto.builder()
                .code("code")
                .clientId(client.getClientId())
                .scopes(Set.of("openid"))
                .subject(subId.toString())
                .redirectUri(new URI("http://redirect-uri"))
                .nonce("nonce")
                .codeChallenge("codeChallenge")
                .codeChallengeMethod("codeChallengeMethod")
                .build();

        user = new User();
        user.setId(subId);
        user.setUsername("username");
    }

    @DisplayName("Should Authorization Code With Confidential Client Successfully")
    @Test
    void shouldAuthorizationCodeWithConfidentialClientSuccessfully() {
        authorizationCode.setCodeChallenge(null);

        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
        when(authorizationCodeService.getAuthorizationCode(any(), any())).thenReturn(authorizationCode);
        when(clientAuthenticationProvider
                .authenticate(new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret())))
                .thenReturn(new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret(), client.getGrantTypes().stream().map(a -> new SimpleGrantedAuthority(a.getGrant())).collect(Collectors.toList())));
        when(userRepository.findById(any())).thenReturn(Optional.of(user));
        when(serverConfiguration.getAccessToken()).thenReturn(getAccessTokenConfig());
        when(serverConfiguration.getRefreshToken()).thenReturn(getRefreshTokenConfig());
        when(serverConfiguration.getIdToken()).thenReturn(getIdTokenConfig());
        when(accessTokenService.createToken(any())).thenReturn(AccessTokenDto.builder().token("token").build());
        when(refreshTokenService.createToken(any())).thenReturn(RefreshTokenDto.builder().token(RandomStringUtils.random(48, true, true)).build());

        when(idTokenService.createToken(any())).thenReturn(IdTokenDto.builder().token("token").build());

        TokenResponseDto tokenResponse =
                authorizationCodeTokenService.getToken(authorizationHeader, tokenRequest);

        assertThat(tokenResponse.getAccessToken())
            .isNotNull();

        assertThat(tokenResponse.getRefreshToken().length())
            .isEqualTo(48);

        assertThat(tokenResponse.getIdToken())
                .isNotNull();

        verify(clientRepository, times(1)).findByClientId(any());
        verify(clientAuthenticationProvider, times(1)).authenticate(any());
        verify(authorizationCodeService, times(1)).getAuthorizationCode(any(), any());
        verify(userRepository, times(1)).findById(any());
        verify(serverConfiguration, times(1)).getAccessToken();
        verify(serverConfiguration, times(1)).getRefreshToken();
        verify(serverConfiguration, times(1)).getIdToken();
        verify(accessTokenService, times(1)).createToken(any());
        verify(refreshTokenService, times(1)).createToken(any());
        verify(idTokenService, times(1)).createToken(any());
    }

    @DisplayName("Test Authorization Code Token Exceptions")
    @Nested
    class TestAuthorizationCodeTokenExceptions {

        @DisplayName("Invalid Client Credentials Throws Exception")
        @Test
        void invalidClientCredentialsThrowsException() {
            TokenResponseDto tokenResponse = null;
            try {
                tokenResponse = authorizationCodeTokenService.getToken("invalid header", null);
            } catch (BadCredentialsException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
            } finally {
                if(tokenResponse != null) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Invalid Client Id Throws Exception")
        @Test
        void invalidClientIdThrowsException() {
            TokenResponseDto tokenResponse = null;
            try {
                tokenResponse = authorizationCodeTokenService.getToken(authorizationHeader, TokenRequestDto.builder().clientId("clientId").clientSecret("clientSecret").build());
            } catch (InvalidClientException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
            } finally {
                if(tokenResponse != null) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Insufficient Client Grant Type Throws Exception")
        @Test
        void insufficientClientGrantTypeThrowsException() {
            client.setGrantTypes(Set.of(GrantType.PASSWORD));

            when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

            TokenResponseDto tokenResponse = null;
            try {
                tokenResponse = authorizationCodeTokenService.getToken(authorizationHeader, TokenRequestDto.builder().clientId("clientId").clientSecret("clientSecret").build());
            } catch (InvalidGrantException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INSUFFICIENT_CLIENT_GRANT_CODE.getDesc());
            } finally {
                if(tokenResponse != null) {
                    fail("Catch block didn't work");
                }

                verify(clientRepository, times(1)).findByClientId(any());
            }
        }

        @DisplayName("Public Client Without PKCE Throws Exception")
        @Test
        void publicClientWithoutPKCEThrowsException() {
            TokenResponseDto tokenResponseDto = null;
            client.setConfidential(false);
            authorizationCode.setCodeChallenge(null);
            try {
                when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));
                when(authorizationCodeService.getAuthorizationCode(any(), any())).thenReturn(authorizationCode);

                tokenResponseDto = authorizationCodeTokenService.getToken(authorizationHeader, tokenRequest);
            } catch (InvalidRequestException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CLIENT_TYPE.getDesc());
            } finally {
                if(tokenResponseDto != null) {
                    fail("Catch block didn't work");
                }
                verify(clientRepository, times(1)).findByClientId(any());
            }
        }
    }

}