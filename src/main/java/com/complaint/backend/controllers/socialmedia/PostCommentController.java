package com.complaint.backend.controllers.socialmedia;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.dtos.PostCommentDTO;
import com.complaint.backend.services.socialmedia.PostCommentService;

@RestController
@RequestMapping("/api/postcomment")
@CrossOrigin(origins = "http://localhost:5173")
public class PostCommentController {

    @Autowired
    private PostCommentService postCommentService;


    private PostCommentController(PostCommentService postCommentService) {
        this.postCommentService=postCommentService;
    }

    @PostMapping("/createcomment")
    public ResponseEntity<PostCommentDTO>saveComment(@RequestBody PostCommentDTO postCommentDTO){
        PostCommentDTO saveComment=postCommentService.saveComment(postCommentDTO);
        return ResponseEntity.ok(saveComment);

    }

    @GetMapping("/fetchcomments/{postId}")
    public ResponseEntity<List<PostCommentDTO>>findByPost_PostIdOrderByCreatedAtDesc(@PathVariable Long postId){
        return ResponseEntity.ok(postCommentService.findByPost_PostIdOrderByCreatedAtDesc(postId));

    }

}