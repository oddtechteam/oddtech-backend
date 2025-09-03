package com.complaint.backend.controllers;

import com.complaint.backend.dtos.AttendanceDTO;
import com.complaint.backend.entities.Attendance;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.AttendanceRepository;
import com.complaint.backend.repositories.UserRepository;
import com.complaint.backend.cache.FaceEmbeddingCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173")
public class FaceLoginController {

    @Autowired
    private AttendanceRepository attendanceRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private FaceEmbeddingCache embeddingCache;

    public List<Float> parseEmbeddingString(String embeddingStr) {
        List<Float> embeddingList = new ArrayList<>();
        if (embeddingStr != null && !embeddingStr.trim().isEmpty()) {
            // Remove brackets [] if they exist
            embeddingStr = embeddingStr.replaceAll("\\[|\\]", "");
            String[] parts = embeddingStr.split(",");
            for (String part : parts) {
                embeddingList.add(Float.parseFloat(part.trim()));
            }
        }
        return embeddingList;
    }


    @PostMapping("/login-by-face")
    public ResponseEntity<?> loginByFace(@RequestBody FaceLoginRequest request) {
        try {
            // Validate request
            if (request.getEmail() == null || request.getEmail().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Email is required"));
            }

            // Check if embedding exists in cache
            if (!embeddingCache.contains(request.getEmail())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not found or no face registered"));
            }

            // Get stored embedding from cache
            FaceEmbeddingCache.UserEmbedding userEmbedding = embeddingCache.get(request.getEmail());
            List<Float> storedEmbedding = userEmbedding.getEmbedding(); // ✅ Correctly extract embedding

            // Compare embeddings (if needed, otherwise trust frontend comparison)
            if (request.getEmbedding() != null && !request.getEmbedding().isEmpty()) {
                // Optional: Add server-side comparison here
            }

            // Save attendance record
            Attendance attendance = new Attendance();
            attendance.setName(request.getName());
            attendance.setEmail(request.getEmail());
            attendance.setTime(LocalDateTime.now());
            attendance.setLat(request.getLat());
            attendance.setLng(request.getLng());
            attendance.setPhoto(request.getPhoto());
            attendance.setStatus("PRESENT");
            attendanceRepository.save(attendance);

            // Get user role from DB
            Optional<User> user = userRepository.findFirstByEmail(request.getEmail());
            String name = user.map(User::getName).orElse(request.getName());
            String role = user.map(u -> u.getUserRole().name()).orElse("EMPLOYEE");

            // Return success response
            return ResponseEntity.ok(Map.of(
                    "message", "Login recorded successfully",
                    "name", request.getName(),
                    "role", role,
                    "time", attendance.getTime(),
                    "location", request.getLat() + "," + request.getLng()
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // ✅ Optional: View cached embeddings (for testing only)
    @GetMapping("/cache-debug")
    public ResponseEntity<?> getCachedEmbeddings() {
        System.out.println("Current Cache: " + embeddingCache.getAll());
        return ResponseEntity.ok(embeddingCache.getAll());
    }

    @GetMapping("/attendance")
    public ResponseEntity<?> getAllAttendance() {
        try {
            List<Attendance> attendanceList = attendanceRepository.findAll();
            List<AttendanceDTO> responseList = attendanceList.stream()
                    .map(a -> new AttendanceDTO(
                            a.getName(),
                            a.getEmail(),
                            a.getTime(),
                            a.getLat(),
                            a.getLng(),
                            a.getPhoto(),
                            a.getStatus()))
                    .toList();

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(responseList);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Collections.singletonMap("error", "Failed to fetch attendance: " + e.getMessage()));
        }
    }

    // In the /cache endpoint
    @GetMapping("/cache")
    public ResponseEntity<List<Map<String, Object>>> getAllCachedEmbeddings() {
        try {
            Map<String, FaceEmbeddingCache.UserEmbedding> cached = embeddingCache.getAll();

            List<Map<String, Object>> result = cached.entrySet().stream()
                    .map(entry -> {
                        Map<String, Object> map = new HashMap<>();
                        map.put("email", entry.getKey());
                        map.put("name", entry.getValue().getName());
                        map.put("embedding", entry.getValue().getEmbedding());
                        return map;
                    }).toList();

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(result);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.emptyList());
        }
    }


    @GetMapping("/users")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @RequestParam(required = false) String email) {
        try {
            List<User> users;
            if (email != null && !email.isEmpty()) {
                // Return only the requested user
                Optional<User> user = userRepository.findFirstByEmail(email);
                users = user.map(Collections::singletonList).orElse(Collections.emptyList());
            } else {
                // Return all users (for admin purposes)
                users = userRepository.findAll();
            }

            List<Map<String, Object>> userResponses = users.stream().map(user -> {
                Map<String, Object> map = new HashMap<>();
                map.put("name", user.getName());
                map.put("email", user.getEmail());

                String rawEmbedding = user.getFaceEmbedding();

                if (rawEmbedding != null && !rawEmbedding.trim().isEmpty()) {
                    try {
                        List<Float> embeddingList = parseEmbeddingString(rawEmbedding);
                        map.put("faceEmbedding", embeddingList);
                    } catch (Exception e) {
                        System.err.println("Failed to parse face embedding for user: " + user.getEmail());
                        map.put("faceEmbedding", null);
                    }
                } else {
                    map.put("faceEmbedding", null);
                }

                return map;
            }).toList();

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(userResponses);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }



    // 🧾 DTO
    public static class FaceLoginRequest {
        private String name;
        private String email;
        private String time;
        private double lat;
        private double lng;
        private String photo;
        private String status;
        private List<Float> embedding;

        public List<Float> getEmbedding() {
            return embedding;
        }

        public void setEmbedding(List<Float> embedding) {
            this.embedding = embedding;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }

        public String getTime() { return time; }
        public void setTime(String time) { this.time = time; }

        public double getLat() { return lat; }
        public void setLat(double lat) { this.lat = lat; }

        public double getLng() { return lng; }
        public void setLng(double lng) { this.lng = lng; }

        public String getPhoto() { return photo; }
        public void setPhoto(String photo) { this.photo = photo; }

        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }
}
