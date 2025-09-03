package com.complaint.backend.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

 // Automatically returns 404 response
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}