package com.complaint.backend.dtos;

import com.complaint.backend.entities.User;

import java.time.LocalDateTime;

public class PostDTO {
	 private Long postId;  
	 
	 private Long userId;
	  private String userName;
	  private String content;
	  private int likes;
	  private String imageUrl;
	  private LocalDateTime createdAt;
	  private User user;
	  public Long getPostId() {
		  return postId;
	  }
	  public void setPostId(Long postId) {
		  this.postId = postId;
	  }
	  public String getUserName() {
		  return userName;
	  }
	  public void setUserName(String userName) {
		 this.userName = userName;
	  }
	  public String getContent() {
		  return content;
	  }
	  public void setContent(String content) {
		  this.content = content;
	  }
	  public int getLikes() {
		  return likes;
	  }
	  public void setLikes(int likes) {
		  this.likes = likes;
	  }
	  public String getImageUrl() {
		  return imageUrl;
	  }
	  public void setImageUrl(String imageUrl) {
		  this.imageUrl = imageUrl;
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
	 
	  public Long getUserId() {
		  return userId;
	  }
	  public void setUserId(Long userId) {
		  this.userId = userId;
	  }

	  
	  
}
