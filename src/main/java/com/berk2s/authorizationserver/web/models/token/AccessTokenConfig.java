package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.web.models.token.Token;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AccessTokenConfig extends Token {
    private TokenType defaultFormat;
}
