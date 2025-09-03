package com.complaint.backend.entities;



import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;
import java.util.Date;

@Entity
@Table(name = "documents")
@Data
public class Document {
 @Id
 @GeneratedValue(strategy = GenerationType.IDENTITY)
 private Long id;
 
 @Column(nullable = false)
 private String name;
 
 @Column(nullable = false)
 private String type; // pdf, doc, xls, img
 
 @Column(nullable = false)
 private long size; // in bytes
 
 @CreationTimestamp
 @Temporal(TemporalType.DATE)
 private LocalDate uploadDate;
 
 @Column(columnDefinition = "TEXT")
 private String description;
 
 @Column(nullable = false)
 private String filePath;
 
 @Column(name = "user_id", nullable = false)
 private Long userId;
 


public Long getId() {
	return id;
}

public void setId(Long id) {
	this.id = id;
}

public String getName() {
	return name;
}

public void setName(String name) {
	this.name = name;
}

public String getType() {
	return type;
}

public void setType(String type) {
	this.type = type;
}

public long getSize() {
	return size;
}

public void setSize(long size) {
	this.size = size;
}

public LocalDate getUploadDate() {
	return uploadDate;
}

public void setUploadDate(LocalDate uploadDate) {
	this.uploadDate = uploadDate;
}

public String getDescription() {
	return description;
}

public void setDescription(String description) {
	this.description = description;
}

public String getFilePath() {
	return filePath;
}

public void setFilePath(String filePath) {
	this.filePath = filePath;
}

public Long getUserId() {
	return userId;
}

public void setUserId(Long userId) {
	this.userId = userId;
}
}