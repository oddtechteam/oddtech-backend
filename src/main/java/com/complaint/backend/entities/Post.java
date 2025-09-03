package com.complaint.backend.entities;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.List;

@Entity
public class Post {
	 @Id 
	 @GeneratedValue(strategy = GenerationType.IDENTITY)
	  private Long postId;  
	  private String content;
	  
	  @Column(nullable = false)
	  private int likes;
	  
	  private String imageUrl;
	  private LocalDateTime createdAt;

	  @ManyToOne(fetch = FetchType.EAGER)
	  @JoinColumn(name = "user_id")
	  private User user;

	  @OneToMany(mappedBy = "post", cascade = CascadeType.ALL)
	  private List<PostComment> postComment;
	  
	  
	  // Getter & Setters for post.

	  public Long getPostId() {
		  return postId;
	  }

	  public void setPostId(Long postId) {
		  this.postId = postId;
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

	  public List<PostComment> getPostComment() {
		  return postComment;
	  }

	  public void setPostComment(List<PostComment> postComment) {
		  this.postComment = postComment;
	  }

	  
	  
	}

