package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.services.impl.SecurityUserDetailsService;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final SecurityUserDetailsService securityUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        SecurityUserDetails securityUserDetails = securityUserDetailsService.loadUserByUsername(username);

        if(passwordEncoder.matches(password, securityUserDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username,
                    password, securityUserDetails.getAuthorities());
        } else {
            log.warn("Invalid username or password [username: {}]", username);
            throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
        }

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
