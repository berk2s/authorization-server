package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientDetailsServiceTest {

    @Mock
    ClientRepository clientRepository;

    @InjectMocks
    ClientDetailsService clientDetailsService;

    Client client;

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
    }

    @DisplayName("Should Load User By Username Returns Successfully")
    @Test
    void shouldLoadUserByUsernameReturnsSuccessfully() {
        when(clientRepository.findByClientId(any())).thenReturn(Optional.of(client));

        SecurityClientDetails securityClientDetails =
                clientDetailsService.loadUserByUsername(client.getClientId());

        assertThat(securityClientDetails.getUsername())
                .isEqualTo(client.getClientId());

        assertThat(securityClientDetails.getPassword())
                .isEqualTo(client.getClientSecret());

        assertThat(securityClientDetails.getAuthorities().size())
                .isEqualTo(client.getGrantTypes().size());

        assertThat(securityClientDetails.getRedirectUris())
                .isEqualTo(client.getRedirectUris());

        verify(clientRepository, times(1)).findByClientId(any());
    }

    @DisplayName("Invalid Client Id Throws Exception")
    @Test
    void invalidClientIdThrowsException() {
        SecurityClientDetails securityClientDetails = null;
        try {
            securityClientDetails = clientDetailsService.loadUserByUsername("invalidClientId");
        } catch (UsernameNotFoundException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_CLIENT.getDesc());
        } finally {
            if(securityClientDetails != null) {
                fail("Catch block didn't work");
            }
        }
    }
}