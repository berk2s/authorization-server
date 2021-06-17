package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.domain.user.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessTokenCommand {

    User user;

    String clientId;

    Set<String> scopes;

    String nonce;

    Duration duration;

}
