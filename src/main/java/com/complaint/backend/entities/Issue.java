package com.complaint.backend.entities;

import com.complaint.backend.enums.IssueStatus;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class Issue {
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long issueId;

	    private String content;
	    
	    @Enumerated(EnumType.STRING)
	    private IssueStatus status; // "open", "in progress", "closed"

	    private LocalDateTime createdAt;
	   
	    @ManyToOne
	    @JoinColumn(name = "user_id")
	    private User user;

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


		public User getUser() {
			return user;
		}

		public void setUser(User user) {
			this.user = user;
		}
	    
	    

}
