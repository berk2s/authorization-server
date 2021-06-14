package com.berk2s.authorizationserver.domain;

import lombok.*;

import javax.persistence.*;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Client extends BaseEntity {

    @Column(name = "client_id", unique = true)
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "confidential")
    private boolean confidential;

    @ElementCollection
    @CollectionTable(
            name = "GRANT_TYPES",
            joinColumns = @JoinColumn(name = "client_uuid")
    )
    @Column(name = "grant_type")
    private Set<GrantType> grantTypes = new HashSet<>();

    @ElementCollection
    @CollectionTable(
            name = "REDIRECT_URIS",
            joinColumns = @JoinColumn(name = "client_uuid")
    )
    @Column(name = "redirect_uri")
    private Set<URI> redirectUris = new HashSet<>();
}
