package com.complaint.backend.services.auth;

import com.complaint.backend.dtos.SignupRequest;
import com.complaint.backend.dtos.UserDTO;

public interface AuthService {


    UserDTO signup(SignupRequest signupRequest);

    Boolean hasUserWithEmail(String email);
    
}
