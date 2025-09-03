package com.complaint.backend.dtos;

import java.time.LocalDateTime;

import com.complaint.backend.enums.IssueStatus;

public class IssueDTO {
	 private Long issueId;
	 private String content;
	 private IssueStatus status; 

	 private LocalDateTime createdAt;
	 private Long userId;
	 private String userName;
	 public Long getIssueId() {
		 return issueId;
	 }
	 public void setIssueId(Long issueId) {
		 this.issueId = issueId;
	 }
	 public String getContent() {
		 return content;
	 }
	 public void setContent(String content) {
		 this.content = content;
	 }
	 public IssueStatus getStatus() {
		 return status;
	 }
	 public void setStatus(IssueStatus status) {
		 this.status = status;
	 }
	 public LocalDateTime getCreatedAt() {
		 return createdAt;
	 }
	 public void setCreatedAt(LocalDateTime createdAt) {
		 this.createdAt = createdAt;
	 }
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
	 
	 
	 
}
