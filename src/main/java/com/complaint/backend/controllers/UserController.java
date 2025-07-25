package com.complaint.backend.controllers;

import com.complaint.backend.dtos.UserDTO;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/all")
    public ResponseEntity<List<UserDTO>> getAllRegisteredUsers() {
        List<UserDTO> users = userRepository.findAll()
                .stream()
                .map(User::getUserDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }
}
