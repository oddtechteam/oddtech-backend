package com.complaint.backend.controllers.customer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.entities.Complaint;
import com.complaint.backend.services.Customer.ComplaintService;


@RestController
@RequestMapping("/complaint")
public class ComplaintController {
 
    @Autowired 
    private ComplaintService complaintService; 
    
    @PostMapping("/create")
    public ResponseEntity<Complaint> createComplaint(@RequestBody Complaint complaint) 
    { 
        Complaint savedComplaint = complaintService.saveComplaint(complaint); 
        return new ResponseEntity<>(savedComplaint, HttpStatus.CREATED); 
    }
}
