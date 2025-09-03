package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.IssueDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface IssueService {

	 List<IssueDTO> findAll(); 
	    List<IssueDTO> findByUserId(Long userId); 
	    List<IssueDTO> findByStatus(String status);
	    List<IssueDTO> findAllByOrderByCreatedAtDesc();
	    public IssueDTO createIssue(IssueDTO issueDTO);
	    public void deleteIssue(Long IssueId);
	
}
