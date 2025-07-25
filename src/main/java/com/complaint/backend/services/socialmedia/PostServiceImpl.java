package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.PostDTO;
import com.complaint.backend.entities.Post;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.PostRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class PostServiceImpl implements PostService{
	
	@Autowired
	private PostRepository postRepository;
	
	@Autowired
	private UserRepository userRepository;
	
	public PostServiceImpl(PostRepository postRepository, UserRepository userRepository) {
		this.postRepository=postRepository;
		this.userRepository=userRepository;
	}
	
	private PostDTO convertToDto(Post savedPost) {
		
		PostDTO dto=new PostDTO();
		
		dto.setContent(savedPost.getContent());
		dto.setCreatedAt(savedPost.getCreatedAt());
		dto.setImageUrl(savedPost.getImageUrl());
		dto.setLikes(savedPost.getLikes());
		dto.setPostId(savedPost.getPostId());
		dto.setUserId(savedPost.getUser().getId());
		dto.setUserName(savedPost.getUser().getName());
		
		 
		
		return dto;
		
	}
  
	@Override
	public PostDTO savePost(PostDTO postDTO) {
		
//		 Get current authenticated user's email (from JWT 'sub' field)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // Find user by email
//        
        Optional<User> userOptional = userRepository.findFirstByEmail(email);
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with email: " + email);
        }
        
        
        Post post=new Post();
        post.setContent(postDTO.getContent());
        post.setCreatedAt(LocalDateTime.now());
        post.setImageUrl(postDTO.getImageUrl());
        post.setLikes(postDTO.getLikes());
        post.setUser(userOptional.get());          
        Post savedPost= postRepository.save(post);
        
        
        
		return convertToDto(savedPost);  
	}

	@Override
	public Optional<PostDTO> getPostById(Long postId) {
		
		return Optional.empty();
	}

	@Override
	public List<PostDTO> getAllPosts() {
		// TODO Auto-generated method stub 
		return null;
	}

	@Override
	public List<PostDTO> getPostsByUserName(String userName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<PostDTO> getPostsByUserId(Long userId) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<PostDTO> getPostsByPostId(Long postId) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<PostDTO>findAllPostsWithUserOrderedByCreatedAtDesc() {
		  
		return postRepository.findAllPostsWithUserOrderedByCreatedAtDesc()
				.stream()
				.map(this::convertToDto)
				.collect(Collectors.toList());
	} 
 
		

	@Override
	public void deletePost(Long postId) {
		
		
	}
	
	
	
	
	//save image and use it
	
	@Override
	public String saveImageAndReturnPath(MultipartFile file) {
	    try {
	        // Validate file type
	        String contentType = file.getContentType();
	        if (contentType == null || 
	            !(contentType.equals("image/jpeg") || contentType.equals("image/png"))) {
	            throw new RuntimeException("Only JPG and PNG images are allowed");
	        }

	        // Validate file size (e.g., limit to 5MB)
	        if (file.getSize() > 5 * 1024 * 1024) {
	            throw new RuntimeException("File size exceeds the 5MB limit");
	        }

	        // Save file
	        String uploadDir = "D:\\ProjectPost";
	        String fileName = UUID.randomUUID() + "_" + file.getOriginalFilename();
	        Path filePath = Paths.get(uploadDir, fileName);

	        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

	        return "/uploads/" + fileName;

	    } catch (IOException e) {
	        throw new RuntimeException("Failed to save image", e);
	    }
	}

	@Override
	public List<PostDTO> findAllByOrderByCreatedAtDesc() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PostDTO getLikesByPostID(Long postId) {
		
		// Get current authenticated user's email (from JWT 'sub' field)
	        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	        String email = authentication.getName();

	        // Find user by email
        
	        Optional<User> userOptional = userRepository.findFirstByEmail(email);
	        if (userOptional.isEmpty()) {
	            throw new RuntimeException("User not found with email: " + email);
	        }
		
		
		    Post post = postRepository.findById(postId)
		        .orElseThrow(() -> new RuntimeException("Post not found with id: " + postId));

		    post.setLikes(post.getLikes() + 1); // increment likes
		    Post updatedPost = postRepository.save(post);

		    return convertToDto(updatedPost); // return updated post DTO
		}

	}
	
	
	
	


