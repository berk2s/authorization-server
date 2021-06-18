package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.web.exceptions.JWTException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.IdGenerator;

import java.text.ParseException;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JWTServiceImpl implements JWTService {

    private final JwtPkiConfiguration jwtPkiConfiguration;
    private final IdGenerator idGenerator;

    @Override
    public String createJWT(JWTCommand jwtCommand) {
        try {
            SecurityDetails userDetails;

            if(jwtCommand.getUserDetails() instanceof SecurityUserDetails) {
                userDetails = (SecurityUserDetails) jwtCommand.getUserDetails();
            } else {
                userDetails = (SecurityClientDetails) jwtCommand.getUserDetails();
            }

            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getId().toString())
                    .issuer(jwtPkiConfiguration.getIssuer())
                    .audience(new ArrayList<>(jwtCommand.getAudiences()))
                    .issueTime(new Date())
                    .notBeforeTime(new Date())
                    .expirationTime(Date.from(jwtCommand.getExpiryDateTime().atZone(ZoneId.systemDefault()).toInstant()))
                    .jwtID(idGenerator.generateId().toString());

            jwtClaimsSetBuilder.claim("scope", String.join(" ", jwtCommand.getScopes()));
            jwtClaimsSetBuilder.claim("username", String.join(" ", userDetails.getUsername()));
            for (Map.Entry<String, Object> claim: jwtCommand.getClaims().entrySet()) {
                jwtClaimsSetBuilder.claim(claim.getKey(), claim.getValue());
            }

            JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();

            SignedJWT signedJWT = signJwt(jwtClaimsSet);
            signedJWT.sign(jwtPkiConfiguration.getJwsSigner());

            return signedJWT.serialize();
        } catch (JOSEException ex) {
            log.warn("Error while creating jwt: {}", ex.getMessage());
            throw new JWTException(ErrorDesc.SERVER_ERROR.getDesc());
        }
    }

    @Override
    public SignedJWT signJwt(JWTClaimsSet jwtClaimsSet) {
        JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        jwsHeaderBuilder.keyID(jwtPkiConfiguration.getPublicKey().getKeyID());

        return new SignedJWT(jwsHeaderBuilder.build(), jwtClaimsSet);
    }

    @Override
    public JWTClaimsSet parseAndValidate(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            signedJWT.verify(jwtPkiConfiguration.getJwsVerifier());
            return signedJWT.getJWTClaimsSet();
        } catch (JOSEException | ParseException ex) {
            log.warn("Error while parsing jwt: {}", ex.getMessage());
            throw new JWTException(ErrorDesc.SERVER_ERROR.getDesc());
        }
    }
}
