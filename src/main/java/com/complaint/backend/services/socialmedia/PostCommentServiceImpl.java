package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.PostCommentDTO;
import com.complaint.backend.entities.Post;
import com.complaint.backend.entities.PostComment;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.PostCommentRepository;
import com.complaint.backend.repositories.PostRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
@Service  
public class PostCommentServiceImpl implements PostCommentService {
	@Autowired
	private PostCommentRepository postCommentRepository;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PostRepository postRepository;
	
	
	public PostCommentServiceImpl(PostCommentRepository postCommentRepository,UserRepository userRepository,PostRepository postRepository) {
		this.postCommentRepository=postCommentRepository;
		this.postRepository=postRepository;
		this.userRepository=userRepository;
	}
	
	
	private PostCommentDTO convertToDto(PostComment savedPostComment) {
		
		PostCommentDTO dto=new PostCommentDTO();
		dto.setCommentId(savedPostComment.getCommentId());
		dto.setContent(savedPostComment.getContent());  
		dto.setCreatedAt(savedPostComment.getCreatedAt());
		dto.setPostId(savedPostComment.getPost().getPostId());
		dto.setUserId(savedPostComment.getUser().getId());
		dto.setUserName(savedPostComment.getUser().getName());  
		
		return dto;
		
	}

	@Override
	public PostCommentDTO saveComment(PostCommentDTO postCommentDTO) {
		
		 // Get current authenticated user's email (from JWT 'sub' field)
        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // Find user by email
        Optional<User> userOptional = userRepository.findFirstByEmail(email);
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with email: " + email);
        }
        
        Optional<Post> postOptional = postRepository.findById(postCommentDTO.getPostId());
        if (postOptional.isEmpty()) {
            throw new RuntimeException("Post not found with id: " + postCommentDTO.getPostId());
        }
        
        PostComment postComment=new PostComment();
        postComment.setCommentId(postCommentDTO.getCommentId());
        postComment.setContent(postCommentDTO.getContent());
        postComment.setCreatedAt(LocalDateTime.now());
        postComment.setPost(postOptional.get());
        postComment.setUser(userOptional.get());
        
        PostComment savedPostComment=postCommentRepository.save(postComment);
		return convertToDto(savedPostComment);   
	}
	
	

	

	@Override
	public void deleteComment(Long commentId) {
		postCommentRepository.deleteById(commentId);  
	}


	@Override
	public List<PostCommentDTO> findByPost_PostIdOrderByCreatedAtDesc(Long postId) {
		
		return postCommentRepository.findByPost_PostIdOrderByCreatedAtDesc(postId)
				.stream()
				.map(this::convertToDto)  
				.collect(Collectors.toList());  
	}

}
