package com.berk2s.authorizationserver.web.models.token;

import com.berk2s.authorizationserver.domain.UserType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshTokenDto {

    private Long id;

    private String token;

    private String subject;

    private String clientId;

    private UserType userType;

    private LocalDateTime issueTime;

    private LocalDateTime notBefore;

    private LocalDateTime expiryDateTime;

}
