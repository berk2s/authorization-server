package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.IdTokenService;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.web.models.token.IdTokenDto;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class IdTokenServiceImpl implements IdTokenService {

    private final JWTService jwtService;

    @Override
    public IdTokenDto createToken(TokenCommand tokenCommand) {
        LocalDateTime expiryDateTime = LocalDateTime.now().plusMinutes(tokenCommand.getDuration().toMinutes());

        SecurityUserDetails securityUserDetails = (SecurityUserDetails) tokenCommand.getUserDetails();

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", securityUserDetails.getName()
                + " "
                + securityUserDetails.getLastName());
        claims.put("given_name", securityUserDetails.getName());
        claims.put("scopes",  "openid profile offline_access");
        claims.put("profile",  securityUserDetails.getLastName());
        claims.put("last_name",  securityUserDetails.getLastName());

        Set<String> scopes = new HashSet<>(tokenCommand.getScopes());
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("offline_access");

        JWTCommand jwtCommand = JWTCommand.builder()
                .userDetails(tokenCommand.getUserDetails())
                .nonce(tokenCommand.getNonce())
                .clientId(tokenCommand.getClientId())
                .scopes(scopes)
                .audiences(Set.of(tokenCommand.getClientId()))
                .expiryDateTime(expiryDateTime)
                .claims(claims)
                .build();

        log.info("Id token is created for the given user [user: {}]", securityUserDetails.getId().toString());

        return IdTokenDto.builder()
                .token(jwtService.createJWT(jwtCommand))
                .expiry(expiryDateTime)
                .build();
    }

}
