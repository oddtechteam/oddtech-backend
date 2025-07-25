package com.complaint.backend.repositories;

import com.complaint.backend.entities.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PostRepository extends JpaRepository<Post, Long>{
	
List <Post> findByUserName(String userName);
List<Post>findByUserId(Long userId);
List<Post>findByPostId(Long postId);
List<Post> findAllByOrderByCreatedAtDesc();

@Query("SELECT p FROM Post p JOIN FETCH p.user ORDER BY p.createdAt DESC")

List<Post> findAllPostsWithUserOrderedByCreatedAtDesc(); // with user fetch


}
