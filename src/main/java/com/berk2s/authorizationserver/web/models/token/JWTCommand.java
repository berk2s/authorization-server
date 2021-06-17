package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JWTCommand {

    SecurityDetails userDetails;

    String clientId;

    String nonce;

    Set<String> audiences;

    Set<String> scopes;

    LocalDateTime expiryDateTime;

    Map<String, Object> claims = new HashMap<>();

}
