package com.complaint.backend.controllers.socialmedia;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.complaint.backend.dtos.PostDTO;
import com.complaint.backend.services.socialmedia.PostService;

@RestController
@RequestMapping("/api/post")
@CrossOrigin(origins = "http://localhost:5173")
public class PostController {

	@Autowired
	private PostService postService;

	private PostController(PostService postService) {
		this.postService=postService;
	}

//	@PostMapping("/createpost")
//	public ResponseEntity<PostDTO>savePost(@RequestBody PostDTO postDto){
//		PostDTO savePost=postService.savePost(postDto);
//		return ResponseEntity.ok(savePost);
//		
//		
//	}


	@PostMapping("/createpost")
	public ResponseEntity<PostDTO> savePost(
			@RequestParam("content") String content,
			@RequestParam(value = "image", required = false) MultipartFile imageFile
	) {
		PostDTO postDto = new PostDTO();
		postDto.setContent(content);

		if (imageFile != null && !imageFile.isEmpty()) {
			String imageUrl = postService.saveImageAndReturnPath(imageFile);
			postDto.setImageUrl(imageUrl);
		}

		PostDTO savedPost = postService.savePost(postDto);
		return ResponseEntity.ok(savedPost);
	}



	@GetMapping("/allpostbydesc")
	public ResponseEntity<List<PostDTO>>findAllPostsWithUserOrderedByCreatedAtDesc(){
		return ResponseEntity.ok(postService.findAllPostsWithUserOrderedByCreatedAtDesc());

	}

	@PutMapping("/like/{postId}")
	public ResponseEntity<PostDTO> getLikesByPostID(@PathVariable Long postId) {
		PostDTO updatedPost = postService.getLikesByPostID(postId);
		return ResponseEntity.ok(updatedPost);
	}





}