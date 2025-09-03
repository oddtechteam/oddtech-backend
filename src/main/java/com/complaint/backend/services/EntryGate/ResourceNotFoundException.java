// src/main/java/com/compaint/backend/exceptions/ResourceNotFoundException.java
package com.complaint.backend.services.EntryGate;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}