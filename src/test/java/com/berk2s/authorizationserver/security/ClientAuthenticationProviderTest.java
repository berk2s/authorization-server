package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.services.impl.ClientDetailsService;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientAuthenticationProviderTest {

    @Mock
    PasswordEncoder passwordEncoder;

    @Mock
    ClientDetailsService clientDetailsService;

    @InjectMocks
    ClientAuthenticationProvider clientAuthenticationProvider;

    Client client;
    SecurityClientDetails securityClientDetails;

    @BeforeEach
    void setUp() throws URISyntaxException {
        client = new Client();
        client.setClientId("clientId");
        client.setClientSecret("clientSecret");
        client.setGrantTypes(Set.of(GrantType.PASSWORD, GrantType.AUTHORIZATION_CODE, GrantType.CLIENT_CREDENTIALS));
        client.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client.setAccountNonExpired(true);
        client.setCredentialsNonExpired(true);
        client.setEnabled(true);
        client.setAccountNonLocked(true);
        client.setConfidential(true);

        securityClientDetails = new SecurityClientDetails(client);
    }

    @DisplayName("Should Client Authentication Successfully")
    @Test
    void clientAuthenticationSuccessfully() {
        when(clientDetailsService.loadUserByUsername(any())).thenReturn(securityClientDetails);
        when(passwordEncoder.matches(any(), any())).thenReturn(true);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) clientAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret()));

        assertThat(usernamePasswordAuthenticationToken.getName())
                .isEqualTo(client.getClientId());

        assertThat(usernamePasswordAuthenticationToken.getCredentials().toString())
                .isEqualTo(client.getClientSecret());

        assertThat(usernamePasswordAuthenticationToken.getAuthorities().size())
                .isEqualTo(client.getGrantTypes().size());

        verify(clientDetailsService, times(1)).loadUserByUsername(any());
    }

    @DisplayName("Invalid Client Secret Throws Exception")
    @Test
    void invalidClientSecretThrowsException() {
        when(clientDetailsService.loadUserByUsername(any())).thenReturn(securityClientDetails);

        try {
            clientAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret()));
        } catch (BadCredentialsException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
        }

        verify(clientDetailsService, times(1)).loadUserByUsername(any());
    }

}