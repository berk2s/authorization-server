package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.IdTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;

public interface IdTokenService {

    IdTokenDto createToken(TokenCommand tokenCommand);

}
