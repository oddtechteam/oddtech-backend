package com.complaint.backend.controllers.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import com.complaint.backend.cache.FaceEmbeddingCache;
import com.complaint.backend.enums.UserRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import com.complaint.backend.dtos.*;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.UserRepository;
import com.complaint.backend.services.auth.AuthService;
import com.complaint.backend.services.jwt.UserService;
import com.complaint.backend.utils.JwtUtil;

import lombok.RequiredArgsConstructor;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final FaceEmbeddingCache faceEmbeddingCache;

    private final AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> signupWithPhoto(@ModelAttribute UserDTO userDTO) {
        if (authService.hasUserWithEmail(userDTO.getEmail())) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                    .body("User already exists with the provided email.");
        }

        try {
            MultipartFile faceImage = userDTO.getFaceImage();
            if (faceImage == null || faceImage.isEmpty()) {
                return ResponseEntity.badRequest().body("Face image is required.");
            }


            // 🧠 Call face embedding API
            String base64Image = "data:image/jpeg;base64," + Base64.getEncoder().encodeToString(faceImage.getBytes());
            RestTemplate restTemplate = new RestTemplate();
            Map<String, String> payload = Map.of("image", base64Image);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    "http://localhost:5005/generate-embedding", payload, Map.class);

            if (!response.getStatusCode().is2xxSuccessful() || !"success".equals(response.getBody().get("status"))) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Face embedding generation failed: " + response.getBody().get("message"));
            }

            String embeddingJson = new ObjectMapper().writeValueAsString(response.getBody().get("embedding"));

            // 🔐 Save user
            SignupRequest signupRequest = new SignupRequest();
            signupRequest.setName(userDTO.getName());
            signupRequest.setEmail(userDTO.getEmail());
            signupRequest.setPassword(userDTO.getPassword());
            signupRequest.setFaceEmbedding(embeddingJson);

            UserDTO createdUser = authService.signup(signupRequest);

            // ✅ Cache embedding if EMPLOYEE
            Optional<User> savedUser = userRepository.findFirstByEmail(createdUser.getEmail());
            savedUser.ifPresent(user -> {
                if (user.getUserRole() == UserRole.EMPLOYEE && user.getFaceEmbedding() != null) {
                    try {
                        List<Float> embedding = new ArrayList<>();
                        String embeddingStr = user.getFaceEmbedding().replaceAll("\\[|\\]", "");
                        for (String part : embeddingStr.split(",")) {
                            embedding.add(Float.parseFloat(part.trim()));
                        }
                        faceEmbeddingCache.put(user.getEmail(), user.getName(),embedding);
                        System.out.println("✅ Cached new user: " + user.getEmail());
                    } catch (Exception e) {
                        System.err.println("⚠️ Failed to parse embedding during signup cache insert.");
                        e.printStackTrace();
                    }
                }
            });

            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to signup user or save face image: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public AuthenticationResponse login(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getEmail(),
                    authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Username or password is incorrect");
        }

        UserDetails userDetails = userService.userDetailsService()
                .loadUserByUsername(authenticationRequest.getEmail());

        Optional<User> optionalUser = userRepository.findFirstByEmail(authenticationRequest.getEmail());

        final String jwt = jwtUtil.generateToken(userDetails);
        AuthenticationResponse response = new AuthenticationResponse();

        optionalUser.ifPresent(user -> {
            response.setJwt(jwt);
            response.setUserRole(user.getUserRole());
            response.setUserId(user.getId());
        });

        return response;
    }
}
