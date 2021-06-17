package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.token.AccessTokenConfig;
import com.berk2s.authorizationserver.web.models.token.IdTokenConfig;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenConfig;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import lombok.Getter;

import java.time.Duration;

@Getter
public class TokenServiceTest {

    private final AccessTokenConfig accessTokenConfig;
    private final RefreshTokenConfig refreshTokenConfig;
    private final IdTokenConfig idTokenConfig;

    public TokenServiceTest() {
        accessTokenConfig = new AccessTokenConfig();
        accessTokenConfig.setLifetime(Duration.ofHours(1));
        accessTokenConfig.setDefaultFormat(TokenType.JWT);

        refreshTokenConfig = new RefreshTokenConfig();
        refreshTokenConfig.setLifetime(Duration.ofHours(1));
        refreshTokenConfig.setMaxLifeTime(Duration.ofHours(2));

        idTokenConfig = new IdTokenConfig();
        idTokenConfig.setLifetime(Duration.ofHours(1));
    }

}
