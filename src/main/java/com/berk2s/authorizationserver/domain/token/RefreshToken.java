package com.berk2s.authorizationserver.domain.token;

import com.berk2s.authorizationserver.domain.UserType;
import lombok.*;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import javax.persistence.Id;
import javax.persistence.Index;
import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@RedisHash("refresh_token")
public class RefreshToken {

    @Id
    private Long id;

    @Indexed
    private String token;

    @Indexed
    private UUID subject;

    private UserType userType;

    private LocalDateTime issueTime;

    private LocalDateTime notBefore;

    private LocalDateTime expiryDateTime;

}
