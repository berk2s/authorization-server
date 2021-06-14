package com.berk2s.authorizationserver.web.models;

import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

@Getter
@Setter
public class RefreshToken extends Token {
    private Duration maxLifeTime;
}
