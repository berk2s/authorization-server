package com.berk2s.authorizationserver.web.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class ErrorResponseDto {
    @JsonIgnore
    private HttpStatus httpStatus;

    @JsonProperty("error")
    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public ErrorResponseDto(ErrorType errorType, String errorDescription, HttpStatus httpStatus){
        this.error = errorType.getError();
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }

    public ErrorResponseDto(ErrorType errorType, HttpStatus httpStatus) {
        this.error = errorType.getError();
        this.errorDescription = httpStatus.getReasonPhrase();
        this.httpStatus = httpStatus;
    }

    public ErrorResponseDto(ErrorType errorType) {
        this.error = errorType.getError();
        this.httpStatus = HttpStatus.BAD_REQUEST;
        this.errorDescription = HttpStatus.BAD_REQUEST.getReasonPhrase();
    }
}
