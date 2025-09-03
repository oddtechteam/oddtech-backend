package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.PostCommentDTO;

import java.util.List;

public interface PostCommentService {
	PostCommentDTO saveComment(PostCommentDTO postCommentDTO);
    void deleteComment(Long commentId); 
    List<PostCommentDTO> findByPost_PostIdOrderByCreatedAtDesc(Long postId);

}
