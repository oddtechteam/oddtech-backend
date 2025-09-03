package com.complaint.backend.repositories;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.complaint.backend.entities.LeaveManagement;
import com.complaint.backend.entities.Task;
import com.complaint.backend.enums.LeaveApplicationStatus;

public interface LeaveManagementRepository extends JpaRepository<LeaveManagement, Long> {
	List<LeaveManagement> findByLeaveStatus(LeaveApplicationStatus leaveStatus);

    List<LeaveManagement> findByStartDateBetween(Date startDate, Date endDate);

    Long countByLeaveStatus(LeaveApplicationStatus leaveStatus);
    
    List<LeaveManagement>findByUserId(Long userId);
 
     Long countByUserIdAndLeaveStatus(Long userId, LeaveApplicationStatus leaveStatus);

    List<LeaveManagement> findByUserIdAndLeaveType(Long userId, String leaveType);

    List<LeaveManagement> findByUserIdAndStartDateBetween(Long userId, Date startDate, Date endDate);
    

}
