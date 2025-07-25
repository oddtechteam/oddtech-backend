package com.complaint.backend.dtos;

import java.time.LocalDateTime;

public class NoteDTO {
	 private Long noteId;

	    private String content;

	    private LocalDateTime createdAt;
	    private Long userId;
	    private String userName;
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
