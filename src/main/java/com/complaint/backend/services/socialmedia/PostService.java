package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.PostDTO;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;
public interface PostService {
	
	 public PostDTO savePost(PostDTO postDTO);

	    // Get post by ID
	    public Optional<PostDTO> getPostById(Long postId);

	    // Get all posts
	    public List<PostDTO> getAllPosts();

	    // Get posts by user name
	    public List<PostDTO> getPostsByUserName(String userName);

	    // Get posts by user ID
	    public List<PostDTO> getPostsByUserId(Long userId);

	    // Get post by post ID
	    public List<PostDTO> getPostsByPostId(Long postId);

	    // Get all posts ordered by createdAt descending
		public List<PostDTO> findAllByOrderByCreatedAtDesc();

	    // Delete post by ID
	    public void deletePost(Long postId);

		String saveImageAndReturnPath(MultipartFile file);
		public List<PostDTO> findAllPostsWithUserOrderedByCreatedAtDesc(); // with user fetch

		PostDTO getLikesByPostID(Long postId);


}
