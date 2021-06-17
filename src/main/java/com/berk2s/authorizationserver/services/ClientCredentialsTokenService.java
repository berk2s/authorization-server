package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.TokenRequestDto;
import com.berk2s.authorizationserver.web.models.token.TokenResponseDto;

public interface ClientCredentialsTokenService {

    TokenResponseDto getToken(String authorizationHeader, TokenRequestDto tokenRequest);

}
