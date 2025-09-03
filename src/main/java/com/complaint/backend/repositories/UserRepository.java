package com.complaint.backend.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository. JpaRepository;
import org.springframework.stereotype. Repository;

import com.complaint.backend.entities.User;
import com.complaint.backend.enums.UserRole;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserRole(UserRole userRole);

    Optional<User> findFirstByEmail(String email);


    List<User> findAllByUserRole(UserRole userRole);
}