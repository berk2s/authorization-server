package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.services.impl.SecurityUserDetailsService;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserAuthenticationProviderTest {

    @Mock
    PasswordEncoder passwordEncoder;

    @Mock
    SecurityUserDetailsService securityUserDetailsService;

    @InjectMocks
    UserAuthenticationProvider userAuthenticationProvider;

    User user;
    SecurityUserDetails securityUserDetails;
    UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");
        user.setPassword("password");
        user.setAuthorities(Set.of(Authority.builder().authorityName("authority").build()));

        securityUserDetails = new SecurityUserDetails(user);
    }

    @DisplayName("Authenticate User Successfully")
    @Test
    void authenticateUserSuccessfully() {
        when(passwordEncoder.matches(any(), any())).thenReturn(true);
        when(securityUserDetailsService.loadUserByUsername(any())).thenReturn(securityUserDetails);

        UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) userAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        assertThat(authenticationToken.getName())
                .isEqualTo(user.getUsername());

        assertThat(authenticationToken.getCredentials().toString())
                .isEqualTo(user.getPassword());

        assertThat(authenticationToken.getAuthorities().size())
                .isEqualTo(securityUserDetails.getAuthorities().size());

        verify(passwordEncoder, times(1)).matches(any(), any());
        verify(securityUserDetailsService, times(1)).loadUserByUsername(any());
    }

    @DisplayName("Unmatching passwords")
    @Test
    void unmatchingPasswords() {
        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            when(passwordEncoder.matches(any(), any())).thenReturn(false);
            when(securityUserDetailsService.loadUserByUsername(any())).thenReturn(securityUserDetails);

            authenticationToken = (UsernamePasswordAuthenticationToken) userAuthenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        } catch (BadCredentialsException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.BAD_CREDENTIALS.getDesc());
        } finally {
            if(authenticationToken != null) {
                fail("Catch block didn't work");
            }

            verify(passwordEncoder, times(1)).matches(any(), any());
            verify(securityUserDetailsService, times(1)).loadUserByUsername(any());
        }

    }

}