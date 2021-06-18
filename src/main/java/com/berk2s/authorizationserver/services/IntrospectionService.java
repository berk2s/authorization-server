package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.IntrospectionRequestDto;
import com.berk2s.authorizationserver.web.models.IntrospectionResponseDto;

public interface IntrospectionService {
    IntrospectionResponseDto getTokenInfo(String authenticationHeader, IntrospectionRequestDto introspectionRequest);
}
