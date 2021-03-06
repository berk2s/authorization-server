package com.berk2s.authorizationserver.utils;

public enum AuthorizationType {
    BEARER("Bearer"),
    BASIC("Basic");

    private final String type;

    AuthorizationType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public String getTypeWithBlank() {
        return type + " ";
    }

    @Override
    public String toString() {
        return type;
    }
}
