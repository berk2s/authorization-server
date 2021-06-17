package com.berk2s.authorizationserver.config;

import com.berk2s.authorizationserver.web.models.token.AccessTokenConfig;
import com.berk2s.authorizationserver.web.models.token.IdTokenConfig;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenConfig;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.net.URI;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Component
@ConfigurationProperties("authorization-server")
public class ServerConfiguration {

    private URI issuer;
    private AccessTokenConfig accessToken;
    private IdTokenConfig idToken;
    private RefreshTokenConfig refreshToken;

    private String privateKeyPath;
    private String publicKeyPath;

}
