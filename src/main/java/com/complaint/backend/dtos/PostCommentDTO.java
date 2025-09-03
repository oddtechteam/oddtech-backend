package com.complaint.backend.dtos;

import java.time.LocalDateTime;

public class PostCommentDTO {
	
	 private Long commentId;

	  private String content;
	  private LocalDateTime createdAt;
	  private Long postId;
	  private Long userId;
	  private String userName;
	  
	  
	  public Long getCommentId() {
		  return commentId;
	  }
	  public void setCommentId(Long commentId) {
		  this.commentId = commentId;
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
	  public Long getPostId() {
		  return postId;
	  }
	  public void setPostId(Long postId) {
		  this.postId = postId;
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
