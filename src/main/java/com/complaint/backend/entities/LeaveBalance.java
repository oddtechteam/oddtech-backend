package com.complaint.backend.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name="leave_balance")
public class LeaveBalance {
	
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
private Long leaveBalanceId;
	
	@OneToOne
	@JoinColumn(name="user_id", nullable=false)
	private User user;
	
	@Column(nullable = false, columnDefinition = "INT DEFAULT 10")
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
	public User getUser() {
		return user;
	}
	public void setUser(User user) {
		this.user = user;
	}
	public int getEarnedLeave() {
		return earnedLeave;
	}
	public void setEarnedLeave(int earnedLeave) {
		this.earnedLeave = earnedLeave;
	}
	
	
	
	
}
