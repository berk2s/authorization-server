package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;

public interface RefreshTokenService extends TokenService {

    RefreshTokenDto getToken(String token);

    RefreshTokenDto createToken(TokenCommand tokenCommand);

}
