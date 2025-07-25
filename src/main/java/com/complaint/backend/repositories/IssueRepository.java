package com.complaint.backend.repositories;

import com.complaint.backend.entities.Issue;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IssueRepository extends JpaRepository<Issue, Long>{


    List<Issue> findAll(); 
    List<Issue> findByUserId(Long userId); 
    List<Issue> findByStatus(String status);
    List<Issue> findAllByOrderByCreatedAtDesc();

}
