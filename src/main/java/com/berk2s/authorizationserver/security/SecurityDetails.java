package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.BaseEntity;

import java.util.UUID;

public abstract class SecurityDetails {

    private final BaseEntity entity;

    public SecurityDetails(BaseEntity entity) {
        this.entity = entity;
    }

    public UUID getId() {
        return entity.getId();
    }

    public Object getAuthorities() {
        return null;
    }

}

