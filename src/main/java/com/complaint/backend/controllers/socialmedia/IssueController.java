package com.complaint.backend.controllers.socialmedia;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.dtos.IssueDTO;
import com.complaint.backend.services.socialmedia.IssueService;

@RestController
@RequestMapping("/api/issue")
@CrossOrigin(origins = "http://localhost:5173")
public class IssueController {
		@Autowired
		private IssueService issueService;
		
		
		private IssueController(IssueService issueservice) {
			this.issueService=issueservice;
		}
		
		
		@PostMapping("/createissue")  
		public ResponseEntity<IssueDTO>createIssue(@RequestBody IssueDTO issueDTO){
			IssueDTO createdIssue=issueService.createIssue(issueDTO);
			return ResponseEntity.ok(createdIssue);
		}
		
		@GetMapping("/allissues")
		public ResponseEntity<List<IssueDTO>>getAllIssue(){
			return ResponseEntity.ok(issueService.findAllByOrderByCreatedAtDesc());  
		}
}
