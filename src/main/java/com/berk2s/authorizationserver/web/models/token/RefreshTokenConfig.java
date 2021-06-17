package com.berk2s.authorizationserver.web.models.token;

import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

@Getter
@Setter
public class RefreshToken extends Token {
    private Duration maxLifeTime;
}
