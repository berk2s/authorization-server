package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityUserDetailsServiceTest {

    @Mock
    UserRepository userRepository;

    @InjectMocks
    SecurityUserDetailsService securityUserDetailsService;

    User user;
    UUID userId;
    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");
    }

    @DisplayName("Load User By Username Successfully")
    @Test
    void loadUserByUsernameSuccessfully() {
        when(userRepository.findByUsername(any())).thenReturn(Optional.of(user));

        SecurityUserDetails securityUserDetails = securityUserDetailsService.loadUserByUsername(user.getUsername());

        assertThat(securityUserDetails.getId())
                .isEqualTo(userId);

        assertThat(securityUserDetails.getUsername())
                .isEqualTo(user.getUsername());

        verify(userRepository, times(1)).findByUsername(any());
    }

    @DisplayName("Invalid username throws Exception")
    @Test
    void invalidUsernameThrowsException() {

        SecurityUserDetails securityUserDetails = null;

        try {
            securityUserDetails = securityUserDetailsService.loadUserByUsername("invalidUsername");
        } catch (UsernameNotFoundException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo(ErrorDesc.INVALID_USER.getDesc());
        } finally {
            if(securityUserDetails != null) {
                fail("Catch block didn't work");
            }


        }

    }

}