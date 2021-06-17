package com.berk2s.authorizationserver.web.models.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IdTokenDto {
    private String token;

    private LocalDateTime expiry;
}
