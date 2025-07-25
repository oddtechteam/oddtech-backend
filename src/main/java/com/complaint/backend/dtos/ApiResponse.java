package com.complaint.backend.dtos;

public class ApiResponse<T> {
    private String message;
    private T data;
    private String error;

    // Success constructor
    public static <T> ApiResponse<T> success(String message, T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.message = message;
        response.data = data;
        return response;
    }

    // Error constructor
    public static ApiResponse<Void> error(String error) {
        ApiResponse<Void> response = new ApiResponse<>();
        response.error = error;
        return response;
    }

    // Getters and Setters
    public String getMessage() { return message; }
    public T getData() { return data; }
    public String getError() { return error; }
}