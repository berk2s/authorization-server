package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.BaseEntity;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

public abstract class SecurityDetails {

    private final BaseEntity entity;

    public SecurityDetails(BaseEntity entity) {
        this.entity = entity;
    }

    public UUID getId() {
        return entity.getId();
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    public String getUsername() { return null; }

}

