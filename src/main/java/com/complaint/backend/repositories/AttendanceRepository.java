package com.complaint.backend.repositories;

import com.complaint.backend.entities.Attendance;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;

public interface AttendanceRepository extends JpaRepository<Attendance, Long> {
    boolean existsByEmailAndTimeBetween(String email, LocalDateTime startTime, LocalDateTime endTime);

    boolean existsByNameAndTimeBetween(String name, LocalDateTime start, LocalDateTime end);
    List<Attendance> findByEmailOrderByTimeDesc(String email);
    List<Attendance> findAllByOrderByTimeDesc();
}