package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.UserType;
import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.repository.RefreshTokenRepository;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.RefreshTokenService;
import com.berk2s.authorizationserver.web.exceptions.TokenNotFoundException;
import com.berk2s.authorizationserver.web.mappers.TokenMapper;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import com.berk2s.authorizationserver.web.models.token.TokenCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@RequiredArgsConstructor
@Service
public class RefreshTokenServiceImpl implements RefreshTokenService  {

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenMapper tokenMapper;

    @Override
    public RefreshTokenDto getToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(token)
                .orElseThrow(() -> {
                    log.warn("Cannot find refresh token by given token [token: {}]", token);
                    throw new TokenNotFoundException(ErrorDesc.INVALID_TOKEN.getDesc());
                });

        return tokenMapper.refreshTokenToRefreshTokenDto(refreshToken);
    }

    @Override
    public RefreshTokenDto createToken(TokenCommand tokenCommand) {
        LocalDateTime issueTime = LocalDateTime.now();
        LocalDateTime expiryDateTime = issueTime.plusMinutes(tokenCommand.getDuration().toMinutes());

        String token = randomString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUserType(userType(tokenCommand.getUserDetails()));
        refreshToken.setIssueTime(issueTime);
        refreshToken.setNotBefore(issueTime);
        refreshToken.setExpiryDateTime(expiryDateTime);
        refreshToken.setSubject(tokenCommand.getUserDetails().getId());
        refreshToken.setClientId(tokenCommand.getClientId());

        log.info("Refresh token is created for the given user [user: {}]", tokenCommand.getUserDetails().getId().toString());

        return tokenMapper.refreshTokenToRefreshTokenDto(refreshTokenRepository.save(refreshToken));
    }

    @Override
    public void deleteToken(String token) {
        log.info("Refresh token is deleted [token: {}]", token);
        refreshTokenRepository.deleteByToken(token);
    }

    private String randomString() {
        return RandomStringUtils.random(48, true, true);
    }

    private UserType userType(SecurityDetails securityDetails) {
        if(securityDetails instanceof SecurityUserDetails) {
            return UserType.END_USER;
        } else if (securityDetails instanceof SecurityClientDetails) {
            return UserType.CLIENT;
        }

        return UserType.CLIENT;
    }
}
