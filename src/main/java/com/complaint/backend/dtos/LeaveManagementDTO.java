package com.complaint.backend.dtos;

import java.util.Date;

import com.complaint.backend.enums.LeaveApplicationStatus;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;
@Data
public class LeaveManagementDTO {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long leaveId;
private String leaveType;
private Date startDate;
private Date endDate;
private String reason;
private Long userId;
private String userName;
@Enumerated(EnumType.STRING)
private LeaveApplicationStatus leaveStatus;





public Long getUserId() {
	return userId;
}

public void setUserId(Long userId) {
	this.userId = userId;
}

public String getUserName() {
	return userName;
}

public void setUserName(String userName) {
	this.userName = userName;
}

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
public LeaveApplicationStatus getLeaveStatus() {
	return leaveStatus;
}
public void setLeaveStatus(LeaveApplicationStatus leaveStatus) {
	this.leaveStatus=leaveStatus;
}

public void setEmployee(String username) {
	// TODO Auto-generated method stub
	
}





}

