package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

public interface JWTService  {
    String createJWT(JWTCommand jwtCommand);

    SignedJWT signJwt(JWTClaimsSet jwtClaimsSet);

    JWTClaimsSet parseAndValidate(String token);

}
