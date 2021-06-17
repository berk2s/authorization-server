package com.berk2s.authorizationserver.web.exceptions;

import com.berk2s.authorizationserver.web.models.ErrorType;
import com.berk2s.authorizationserver.web.models.ErrorResponseDto;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(InvalidSecurityUserDetailsException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidSecurityUserDetailsException(InvalidSecurityUserDetailsException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_GRANT, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(InvalidClientException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidClientException(InvalidClientException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_CLIENT, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidRequestException(InvalidRequestException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_REQUEST, ex.getMessage(), HttpStatus.BAD_REQUEST));
    }

    @ExceptionHandler(InvalidRedirectUriException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidRedirectUriException(InvalidRedirectUriException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_REQUEST, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(ServerException.class)
    public ResponseEntity<ErrorResponseDto> handleServerException(ServerException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.SERVER_ERROR, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponseDto> handleBadCredentialsException(BadCredentialsException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_GRANT, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(InvalidGrantException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidGrantException(InvalidGrantException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_GRANT, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(CodeChallengeException.class)
    public ResponseEntity<ErrorResponseDto> handleCodeChallengeException(CodeChallengeException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_REQUEST, ex.getMessage(), HttpStatus.BAD_REQUEST));
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_CLIENT, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleTokenNotFoundException(TokenNotFoundException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.INVALID_TOKEN, ex.getMessage(), HttpStatus.UNAUTHORIZED));
    }

    @ExceptionHandler(JWTException.class)
    public ResponseEntity<ErrorResponseDto> handleJWTCreatingException(JWTException ex) {
        return errorResponse(new ErrorResponseDto(ErrorType.SERVER_ERROR, ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR));
    }

    private ResponseEntity<ErrorResponseDto> errorResponse(ErrorResponseDto errorResponseDto){
        return new ResponseEntity<>(errorResponseDto, errorResponseDto.getHttpStatus());
    }

}
