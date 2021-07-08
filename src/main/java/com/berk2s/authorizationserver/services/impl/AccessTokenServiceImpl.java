package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class AccessTokenServiceImpl implements AccessTokenService {

    private final JWTService jwtService;

    @Override
    public AccessTokenDto createToken(TokenCommand tokenCommand) {
        LocalDateTime expiryDateTime = LocalDateTime.now().plusMinutes(tokenCommand.getDuration().toMinutes());

        SecurityDetails userDetails;

        if(tokenCommand.getUserDetails() instanceof SecurityUserDetails) {
            userDetails = (SecurityUserDetails) tokenCommand.getUserDetails();
        } else {
            userDetails = (SecurityClientDetails) tokenCommand.getUserDetails();
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("scopes", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(authority -> !authority.startsWith("ROLE_")).collect(Collectors.toList()));
        claims.put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(authority -> authority.startsWith("ROLE_")).collect(Collectors.toList()));

        JWTCommand jwtCommand = JWTCommand.builder()
                .userDetails(tokenCommand.getUserDetails())
                .nonce(tokenCommand.getNonce())
                .clientId(tokenCommand.getClientId())
                .scopes(tokenCommand.getScopes())
                .audiences(Set.of(tokenCommand.getClientId()))
                .expiryDateTime(expiryDateTime)
                .claims(claims)
                .build();

        log.info("Access token is created for the given user [userId: {}]", userDetails.getId());

        return AccessTokenDto.builder()
                .token(jwtService.createJWT(jwtCommand))
                .expiry(expiryDateTime)
                .build();
    }

}
