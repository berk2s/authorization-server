package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.web.models.RegisterRequestDto;
import com.berk2s.authorizationserver.web.models.RegisterResponseDto;

public interface RegisterService {
    void register(RegisterRequestDto registerRequest);
}
