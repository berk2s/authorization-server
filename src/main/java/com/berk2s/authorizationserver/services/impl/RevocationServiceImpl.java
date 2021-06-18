package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.security.ClientAuthenticationProvider;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.services.RevocationService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.RevocationRequestDto;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class RevocationServiceImpl implements RevocationService {

    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ClientAuthenticationProvider clientAuthenticationProvider;

    @Override
    public void revokeToken(String authorizationHeader, RevocationRequestDto revocationRequest) {
        ClientCredentialsDto clientCredentials = AuthenticationParser.basicParser(authorizationHeader);

        clientAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken(clientCredentials.getClientId(), clientCredentials.getClientSecret()));

        RefreshTokenDto refreshToken = refreshTokenService.getToken(revocationRequest.getToken());

        refreshTokenRepository.deleteById(refreshToken.getId());
    }
}
