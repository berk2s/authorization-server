package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IntrospectionRequestDto {

    @NotBlank
    private String token;

    @JsonProperty("token_type_hint")
    private String tokenTypeHint;

}
