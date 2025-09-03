package com.complaint.backend.dtos;

public class LoginSuccessResponse {
    private String name;
    private String role;
    private String token;

    // Constructor (updated to include token)
    public LoginSuccessResponse(String name, String role, String token) {
        this.name = name;
        this.role = role;
        this.token = token;
    }

    // Getters and Setters (required for JSON serialization)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}