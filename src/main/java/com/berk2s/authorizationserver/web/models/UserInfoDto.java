package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserInfoDto {
    private String sub;

    private String name;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("first_name")
    private String firstName;

    @JsonProperty("family_name")
    private String familyName;


    @JsonProperty("last_name")
    private String lastName;


    private String nickname;

    @JsonProperty("preferred_username")
    private String preferredUsername;

    private String email;

    @JsonProperty("email_verified")
    private Boolean emailVerified;

    @JsonProperty("phone_number")
    private String phoneNumber;

    @JsonProperty("phone_number_verified")
    private Boolean phoneNumberVerified;

    private String profile;

    private Set<String> roles;

    private Set<String> authorities;

}
