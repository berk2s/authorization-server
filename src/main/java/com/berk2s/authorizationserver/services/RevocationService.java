package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.RevocationRequestDto;

public interface RevocationService {
    void revokeToken(String authorizationHeader, RevocationRequestDto revocationRequest);
}
