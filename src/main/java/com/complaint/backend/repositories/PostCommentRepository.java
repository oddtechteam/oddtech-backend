package com.complaint.backend.repositories;

import com.complaint.backend.entities.PostComment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostCommentRepository extends JpaRepository<PostComment, Long> {
	
    List<PostComment> findByPost_PostIdOrderByCreatedAtDesc(Long postId);

 
 
}
