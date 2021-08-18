package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.security.UserAuthenticationProvider;
import com.berk2s.authorizationserver.services.LoginService;
import com.berk2s.authorizationserver.web.models.LoginRequestDto;
import com.berk2s.authorizationserver.web.models.LoginResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class LoginServiceImpl implements LoginService {

    private final UserAuthenticationProvider userAuthenticationProvider;

    @Override
    public LoginResponseDto login(LoginRequestDto loginRequest) {

        UsernamePasswordAuthenticationToken authentication =
                (UsernamePasswordAuthenticationToken) userAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        return LoginResponseDto.builder()
                .username(authentication.getName())
                .password(authentication.getCredentials().toString())
                .build();
    }
}
