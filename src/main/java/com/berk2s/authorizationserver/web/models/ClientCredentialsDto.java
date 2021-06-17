package com.berk2s.authorizationserver.web.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientCredentialsDto {

    private String clientId;

    private String clientSecret;

}
