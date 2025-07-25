package com.complaint.backend.dtos;

import com.complaint.backend.enums.UserRole;

import lombok.Data;

@Data
public class AuthenticationResponse {
        private String jwt;
        private long userId;
        private UserRole userRole;


}
