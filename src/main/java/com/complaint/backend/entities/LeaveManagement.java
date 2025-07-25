package com.complaint.backend.entities;

import java.time.LocalDate;
import java.util.Date;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import com.complaint.backend.enums.LeaveApplicationStatus;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Entity
@Data
public class LeaveManagement {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long leaveId;
private String leaveType;
private Date startDate;
private Date endDate;
private String reason;

@ManyToOne(fetch = FetchType.EAGER)
@JoinColumn(name = "user_id", nullable = false)
@OnDelete(action = OnDeleteAction.CASCADE)
@JsonIgnore
private User user;

@Enumerated(EnumType.STRING)
private  LeaveApplicationStatus leaveStatus;

public Long getLeaveId() {
	return leaveId;
}

public void setLeaveId(Long leaveId) {
	this.leaveId = leaveId;
}

public String getLeaveType() {
	return leaveType;
}

public void setLeaveType(String leaveType) {
	this.leaveType = leaveType;
}

public Date getStartDate() {
	return startDate;
}

public void setStartDate(Date startDate) {
	this.startDate = startDate;
}

public Date getEndDate() {
	return endDate;
}

public void setEndDate(Date endDate) {
	this.endDate = endDate;
}

public String getReason() {
	return reason;
}

public void setReason(String reason) {
	this.reason = reason;
}

public User getUser() {
	return user;
}

public void setUser(User user) {
	this.user = user;
}


public LeaveApplicationStatus getLeaveStatus() {
	return leaveStatus;
}

public void setLeaveStatus(LeaveApplicationStatus leaveStatus) {
	this.leaveStatus = leaveStatus;
}

public LeaveManagement() {
    // Needed by JPA and when manually creating empty objects
}




}

