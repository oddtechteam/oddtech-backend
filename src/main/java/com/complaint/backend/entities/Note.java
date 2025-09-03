package com.complaint.backend.entities;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class Note {
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long noteId;

	    private String content;

	    private LocalDateTime createdAt;
	  
	    
	    @ManyToOne
	    @JoinColumn(name = "user_id")
	    private User user;

		public Long getNoteId() {
			return noteId;
		}

		public void setNoteId(Long noteId) {
			this.noteId = noteId;
		}

		public String getContent() {
			return content;
		}

		public void setContent(String content) {
			this.content = content;
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
