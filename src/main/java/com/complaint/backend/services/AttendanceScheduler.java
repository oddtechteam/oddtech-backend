package com.complaint.backend.services;

import com.complaint.backend.entities.User;
import com.complaint.backend.entities.Attendance;
import com.complaint.backend.repositories.UserRepository;
import com.complaint.backend.repositories.AttendanceRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class AttendanceScheduler {

    private final UserRepository userRepository;
    private final AttendanceRepository attendanceRepository;

    public AttendanceScheduler(UserRepository userRepository,
                               AttendanceRepository attendanceRepository) {
        this.userRepository = userRepository;
        this.attendanceRepository = attendanceRepository;
    }

    // Runs daily at 11:59 PM

    @Scheduled(cron = "0 0 0 * * ?") // Runs at midnight
    public void initializeDailyAttendance() {
        LocalDate today = LocalDate.now();
        LocalDateTime startOfDay = today.atStartOfDay();

        List<User> allUsers = userRepository.findAll();

        for (User user : allUsers) {
            Attendance absentRecord = new Attendance();
            absentRecord.setName(user.getName());
            absentRecord.setEmail(user.getEmail());
            absentRecord.setTime(startOfDay);
            absentRecord.setStatus("ABSENT");
            absentRecord.setLat(0.0);
            absentRecord.setLng(0.0);
            absentRecord.setPhoto("ABSENT");
            attendanceRepository.save(absentRecord);
        }
    }
}