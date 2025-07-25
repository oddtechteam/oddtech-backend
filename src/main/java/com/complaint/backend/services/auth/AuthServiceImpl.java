package com.complaint.backend.services.auth;

import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.complaint.backend.dtos.SignupRequest;
import com.complaint.backend.dtos.UserDTO;
import com.complaint.backend.entities.User;
import com.complaint.backend.enums.UserRole;
import com.complaint.backend.repositories.UserRepository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;

    @PostConstruct
    private void createAnAdminAccount() {
        Optional<User> optionalUser = userRepository.findByUserRole(UserRole.ADMIN);
        if (optionalUser.isEmpty()) {
            User newAdmin = new User();
            newAdmin.setName("Admin");
            newAdmin.setEmail("admin@test.com");
            newAdmin.setPassword(new BCryptPasswordEncoder().encode("admin"));
            newAdmin.setUserRole(UserRole.ADMIN);
            userRepository.save(newAdmin);
        } else {
            System.out.println("Admin account already exists");
        }
    }

    @Override
    public Boolean hasUserWithEmail(String email) {
        return userRepository.findFirstByEmail(email).isPresent();
    }

    @Override
    public UserDTO signup(SignupRequest signupRequest) {
        try {
            // If embedding is already provided in the request, use it directly
            if (signupRequest.getFaceEmbedding() != null) {
                User user = new User();
                user.setEmail(signupRequest.getEmail());
                user.setName(signupRequest.getName());
                user.setUserRole(UserRole.EMPLOYEE);
                user.setPassword(new BCryptPasswordEncoder().encode(signupRequest.getPassword()));
                user.setFaceEmbedding(signupRequest.getFaceEmbedding());
                return userRepository.save(user).getUserDTO();
            }

            // Otherwise generate new embedding from image
            RestTemplate restTemplate = new RestTemplate();
            Map<String, String> body = Map.of("image", signupRequest.getFaceImageBase64());

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    "http://localhost:5005/generate-embedding", body, Map.class);

            if (!response.getStatusCode().is2xxSuccessful() || !"success".equals(response.getBody().get("status"))) {
                throw new RuntimeException("Face embedding generation failed: " + response.getBody().get("message"));
            }

            ObjectMapper mapper = new ObjectMapper();
            String embeddingJson = mapper.writeValueAsString(response.getBody().get("embedding"));

            User user = new User();
            user.setEmail(signupRequest.getEmail());
            user.setName(signupRequest.getName());
            user.setUserRole(UserRole.EMPLOYEE);
            user.setPassword(new BCryptPasswordEncoder().encode(signupRequest.getPassword()));
            user.setFaceEmbedding(embeddingJson);

            return userRepository.save(user).getUserDTO();
        } catch (Exception e) {
            throw new RuntimeException("Registration failed: " + e.getMessage());
        }
    }

    // Optional: Google login support
//    public User createGoogleUser(String email, String name) {
//        return userRepository.findFirstByEmail(email).orElseGet(() -> {
//            User user = new User();
//            user.setEmail(email);
//            user.setName(name);
//            user.setUserRole(UserRole.EMPLOYEE); // Default role for Google users
//            user.setPassword(null); // No password needed for Google users
//            return userRepository.save(user);
//        });
//    }
}
