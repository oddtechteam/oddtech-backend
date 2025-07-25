package com.complaint.backend.dtos;

import com.complaint.backend.entities.User;

public class LeaveBalanceDTO {
	
	private Long leaveBalanceId;
	private Long userId;
	private int annualLeave= 14;
	private int sickLeave=12;
	private int casualLeave=10;
	private int earnedLeave=20;

	public Long getLeaveBalanceId() {
		return leaveBalanceId;
	}
	public void setLeaveBalanceId(Long leaveBalanceId) {
		this.leaveBalanceId = leaveBalanceId;
	}
	public Long getUserId() {
		return userId;
	}
	public void setUserId(Long userId) {
		this.userId = userId;
	}
	public int getAnnualLeave() {
		return annualLeave;
	}
	public void setAnnualLeave(int annualLeave) {
		this.annualLeave = annualLeave;
	}
	public int getSickLeave() {
		return sickLeave;
	}
	public void setSickLeave(int sickLeave) {
		this.sickLeave = sickLeave;
	}
	public int getCasualLeave() {
		return casualLeave;
	}
	public void setCasualLeave(int casualLeave) {
		this.casualLeave = casualLeave;
	}
	public int getEarnedLeave() {
		return earnedLeave;
	}
	public void setEarnedLeave(int earnedLeave) {
		this.earnedLeave = earnedLeave;
	}
	
	
}
