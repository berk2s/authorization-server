package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@Builder
public class RevocationRequestDto {
    @NotBlank
    private String token;

    @JsonProperty("token_type_hint")
    private String tokenTypeHint;

    public RevocationRequestDto(String token,
                                String token_type_hint) {
        this.token = token;
        this.tokenTypeHint = token_type_hint;
    }


}
