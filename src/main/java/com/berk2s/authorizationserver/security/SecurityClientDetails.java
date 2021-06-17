package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.oauth.Client;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

public class SecurityClientDetails extends SecurityDetails implements UserDetails {

    private final Client client;

    public SecurityClientDetails(Client client) {
        super(client);
        this.client = client;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return client.getGrantTypes()
                .stream()
                .map(g -> new SimpleGrantedAuthority(g.getGrant().toUpperCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return client.getClientSecret();
    }

    @Override
    public String getUsername() {
        return client.getClientId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return client.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return client.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return client.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return client.isEnabled();
    }

    public boolean isConfidential() {
        return client.isConfidential();
    }

    public Set<URI> getRedirectUris() {
        return client.getRedirectUris();
    }

}
