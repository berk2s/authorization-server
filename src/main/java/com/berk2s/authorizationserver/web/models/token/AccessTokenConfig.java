package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.web.models.token.Token;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessToken extends Token {
    private TokenType defaultFormat;
}
