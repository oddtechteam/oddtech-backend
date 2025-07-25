package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.IssueDTO;
import com.complaint.backend.entities.Issue;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.IssueRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
@Service
public class IssueServiceImpl implements IssueService{
	@Autowired
	private IssueRepository issueRepository;
	@Autowired
	private UserRepository userRepository;
	
	
	public IssueServiceImpl(IssueRepository issueRepository, UserRepository userRepository) {
		this.issueRepository=issueRepository;
		this.userRepository=userRepository;
	}
	
	
	private IssueDTO convertToDto(Issue savedIssue) {
		IssueDTO dto=new IssueDTO();
		dto.setContent(savedIssue.getContent());
		dto.setCreatedAt(savedIssue.getCreatedAt());
		dto.setIssueId(savedIssue.getIssueId());
		dto.setStatus(savedIssue.getStatus());
		dto.setUserName(savedIssue.getUser().getName());
		dto.setUserId(savedIssue.getUser().getId());
		return dto;   
	}

	@Override
	public List<IssueDTO> findAll() {
		
		return issueRepository.findAll()
				.stream()
				.map(this::convertToDto)
				.collect(Collectors.toList());  
	}

	@Override
	public List<IssueDTO> findByUserId(Long userId) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IssueDTO> findByStatus(String status) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IssueDTO> findAllByOrderByCreatedAtDesc() {
		return issueRepository.findAllByOrderByCreatedAtDesc()  
				.stream()
				.map(this::convertToDto)
				.collect(Collectors.toList());
	}

	@Override
	public IssueDTO createIssue(IssueDTO issueDTO) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // Find user by email
        Optional<User> userOptional = userRepository.findFirstByEmail(email);
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with email: " + email);
        }
        
        
        Issue issue=new Issue();
        issue.setContent(issueDTO.getContent());
        issue.setCreatedAt(LocalDateTime.now());
        issue.setUser(userOptional.get());
        
        Issue savedIssue=issueRepository.save(issue);
        return convertToDto(savedIssue);  

	}

	@Override
	public void deleteIssue(Long IssueId) {
		// TODO Auto-generated method stub
		
	}

}
