package com.berk2s.authorizationserver.web.models;

import lombok.Getter;

import java.time.Duration;

@Getter
public abstract class Token {
    private Duration lifetime;
}
