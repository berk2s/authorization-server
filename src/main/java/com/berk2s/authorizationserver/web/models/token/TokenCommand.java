package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.security.SecurityDetails;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenCommand {

    SecurityDetails userDetails;

    String subject;

    String clientId;

    Set<String> scopes;

    String nonce;

    Duration duration;

}
