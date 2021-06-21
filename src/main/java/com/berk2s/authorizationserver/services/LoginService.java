package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.LoginRequestDto;
import com.berk2s.authorizationserver.web.models.LoginResponseDto;

public interface LoginService {
    LoginResponseDto login(LoginRequestDto loginRequest);
}
