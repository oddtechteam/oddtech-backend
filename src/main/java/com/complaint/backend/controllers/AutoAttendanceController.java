package com.complaint.backend.controllers;

import com.complaint.backend.entities.Attendance;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.AttendanceRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@RestController
@RequestMapping("/api/attendance")
@CrossOrigin(origins = "*")
public class AutoAttendanceController {

    @Autowired
    private AttendanceRepository attendanceRepository;

    @Autowired
    private UserRepository userRepository;

    private final RestTemplate restTemplate = new RestTemplate();
    private final String FACE_SERVICE_URL = "http://localhost:5005";

    @PostMapping("/check-in-out")
    public ResponseEntity<?> checkInOut(@RequestBody AttendanceRequest request) {
        try {
            // Get user from database
            Optional<User> user = userRepository.findFirstByEmail(request.getEmail());
            if (user.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "User not found"
                ));
            }

            // Create and save attendance record
            Attendance attendance = new Attendance();
            attendance.setName(user.get().getName());
            attendance.setEmail(user.get().getEmail());
            attendance.setTime(LocalDateTime.now());
            attendance.setPhoto(request.getPhoto());
            attendance.setStatus(request.getType().equalsIgnoreCase("in") ? "PRESENT" : "LEFT_OFFICE");
            attendanceRepository.save(attendance);

            // Prepare response
            return ResponseEntity.ok(Map.of(
                    "message", "Attendance recorded successfully",
                    "name", user.get().getName(),
                    "employeeId", "EMP-" + user.get().getId(),
                    "department", user.get().getDepartment() != null ? user.get().getDepartment() : "Engineering",
                    "time", LocalDateTime.now().format(DateTimeFormatter.ofPattern("hh:mm:ss a")),
                    "date", LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEEE, MMMM d, yyyy"))
            ));

        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", e.getMessage()
            ));
        }
    }

    @GetMapping("/records")
    public ResponseEntity<?> getAttendanceRecords(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String search) {
        try {
            List<Attendance> records;
            if (email != null && !email.isEmpty()) {
                records = attendanceRepository.findByEmailOrderByTimeDesc(email);
            } else {
                records = attendanceRepository.findAllByOrderByTimeDesc();
            }

            if (search != null && !search.isEmpty()) {
                records = records.stream()
                        .filter(r -> r.getName().toLowerCase().contains(search.toLowerCase()) ||
                                r.getEmail().toLowerCase().contains(search.toLowerCase()))
                        .toList();
            }

            List<Map<String, Object>> response = records.stream()
                    .map(r -> {
                        Map<String, Object> record = new HashMap<>();
                        record.put("id", r.getId());
                        record.put("type", r.getStatus().equals("PRESENT") ? "in" : "out");
                        record.put("time", r.getTime().format(DateTimeFormatter.ofPattern("hh:mm:ss a")));
                        record.put("date", r.getTime().format(DateTimeFormatter.ofPattern("EEEE, MMMM d, yyyy")));
                        record.put("image", r.getPhoto());
                        record.put("name", r.getName());
                        record.put("employeeId", "EMP-" + r.getId());
                        record.put("department", "Engineering");
                        record.put("status", r.getStatus());
                        return record;
                    })
                    .toList();

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/records/{id}")
    public ResponseEntity<?> deleteRecord(@PathVariable Long id) {
        try {
            attendanceRepository.deleteById(id);
            return ResponseEntity.ok(Map.of("message", "Record deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    public static class AttendanceRequest {
        private String photo;
        private String type;
        private String email;

        public String getPhoto() { return photo; }
        public void setPhoto(String photo) { this.photo = photo; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getEmail() { return email; }  // Add getter
        public void setEmail(String email) { this.email = email; }
    }
}