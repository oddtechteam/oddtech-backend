package com.complaint.backend.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.complaint.backend.entities.LeaveBalance;

public interface LeaveBalanceRepository extends JpaRepository<LeaveBalance, Long> {
	
    LeaveBalance findByUserId(Long userId);


}
