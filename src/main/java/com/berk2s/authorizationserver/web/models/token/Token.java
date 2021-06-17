package com.berk2s.authorizationserver.web.models.token;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

@Getter
@Setter
public abstract class Token {
    private Duration lifetime;
}
