package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AccessTokenService;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.Scope;
import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
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

        List<String> authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(authority -> !authority.startsWith("ROLE_")).collect(Collectors.toList());
        List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(authority -> authority.startsWith("ROLE_")).collect(Collectors.toList());

        for (String _claimedAuthority : tokenCommand.getScopes()) {
            String claimedAuthority = _claimedAuthority.toUpperCase(Locale.ROOT);

            if (EnumUtils.isValidEnum(Scope.class, claimedAuthority) || StringUtils.isBlank(claimedAuthority)) {
                continue;
            }

            if(!authorities.contains(claimedAuthority)) {
                log.warn("The requested authority is not available for the User [userId: {}, authority: {}]", userDetails.getId().toString(), claimedAuthority);
                throw new InvalidGrantException(ErrorDesc.USER_HAS_NOT_SCOPE.getDesc());
            }
        }

        List<String> initialScopes = tokenCommand.getScopes().stream().map(s -> s.toUpperCase(Locale.ROOT)).filter(s -> EnumUtils.isValidEnum(Scope.class, s)).collect(Collectors.toList());

        authorities.addAll(initialScopes);

        claims.put("scopes", authorities);
        claims.put("roles", roles);

        JWTCommand jwtCommand = JWTCommand.builder()
                .userDetails(tokenCommand.getUserDetails())
                .nonce(tokenCommand.getNonce())
                .clientId(tokenCommand.getClientId())
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
