package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.services.impl.ClientDetailsService;
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
public class ClientAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final ClientDetailsService clientDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String clientId = authentication.getName();
        String clientSecret = authentication.getCredentials().toString();

        SecurityClientDetails securityClientDetails = clientDetailsService.loadUserByUsername(clientId);

        if(passwordEncoder.matches(clientSecret, securityClientDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(clientId,
                    clientSecret,
                    securityClientDetails.getAuthorities());
        } else {
            log.warn("Invalid client id or client secret [clientId: {}]", clientId);
            throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
        }

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
