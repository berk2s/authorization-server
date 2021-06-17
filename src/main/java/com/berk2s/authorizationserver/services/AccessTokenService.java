package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.AccessTokenDto;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public interface AccessTokenService {

    AccessTokenDto createToken(TokenCommand tokenCommand);


}
