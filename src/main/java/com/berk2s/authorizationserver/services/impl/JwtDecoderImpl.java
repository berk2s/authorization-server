package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import com.berk2s.authorizationserver.web.exceptions.JWTException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Slf4j
@RequiredArgsConstructor
@Service("jwtDecoder")
public class JwtDecoderImpl implements JwtDecoder {

    private final JwtPkiConfiguration jwtPkiConfiguration;

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            signedJWT.verify(jwtPkiConfiguration.getJwsVerifier());
            return new Jwt(token,
                    signedJWT.getJWTClaimsSet().getIssueTime().toInstant(),
                    signedJWT.getJWTClaimsSet().getExpirationTime().toInstant(),
                    signedJWT.getHeader().toJSONObject(),
                    signedJWT.getJWTClaimsSet().getClaims());
        } catch (IllegalArgumentException | JOSEException | ParseException ex) {
            log.warn("Error while parsing jwt: {}", ex.getMessage());
            throw new JWTException(ErrorDesc.SERVER_ERROR.getDesc());
        }
    }

}
