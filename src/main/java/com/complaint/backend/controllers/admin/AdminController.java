package com.complaint.backend.controllers.admin;

import com.complaint.backend.dtos.LeaveBalanceDTO;
import com.complaint.backend.dtos.LeaveManagementDTO;
import com.complaint.backend.enums.LeaveApplicationStatus;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.dtos.CommentDTO;
import com.complaint.backend.dtos.TaskDTO;
import com.complaint.backend.services.admin.AdminService;

import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Date;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin")
//@CrossOrigin(origins = "http://localhost:4200")
public class AdminController {

    
    private final AdminService adminService;

   

    @GetMapping("/users")
    public ResponseEntity<?> getUsers(){
        return ResponseEntity.ok(adminService.getUsers());

    }

    @GetMapping("/tasks")
    public ResponseEntity<?> getTasks(){
        return ResponseEntity.ok(adminService.getTasks());

    }

    @GetMapping("/task/{id}")
    public ResponseEntity<?> getTasksById(@PathVariable Long id){
        return ResponseEntity.ok(adminService.getTaskById(id));

    }

    @DeleteMapping("/task/{id}")
    public ResponseEntity<?> deleteTask(@PathVariable Long id){
        adminService.deleteTask(id);
        return ResponseEntity.ok(null);

    }

    @PostMapping("/task")
    public ResponseEntity<?> postTask(@RequestBody TaskDTO taskDTO){
        TaskDTO createdTaskDTO = adminService.postTask(taskDTO);
        if (createdTaskDTO == null) return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.status(HttpStatus.CREATED).body(createdTaskDTO);

    }


    @GetMapping("/tasks/search/{title}")
    public ResponseEntity<?> searchTasks(@PathVariable String title){
        return ResponseEntity.ok(adminService.searchTask(title));

    }

    @PutMapping("/task/{id}")
    public ResponseEntity<?> updateTask(@PathVariable Long id, @RequestBody TaskDTO taskDTO){
        TaskDTO updatedTaskDTO = adminService.updateTask(id, taskDTO);
        if (updatedTaskDTO == null) return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.status(HttpStatus.CREATED).body(updatedTaskDTO);

    }

    @PostMapping("/task/comment")
    public ResponseEntity<?> createComment(@RequestParam Long taskId, @RequestParam Long postedBy, @RequestBody String content ){
        CommentDTO createCommentDTO = adminService.createComment(taskId, postedBy, content);
        if (createCommentDTO == null) return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.status(HttpStatus.CREATED).body(createCommentDTO);

    }


    @GetMapping("/task/{taskId}/comments")
    public ResponseEntity<?> getCommentByTask(@PathVariable Long taskId) {
        return ResponseEntity.ok(adminService.getCommentsByTask(taskId));
    }

    // ============================ Leave Management ============================

    @GetMapping("/leave/all")
    public List<LeaveManagementDTO> getAllLeaves() {
        return adminService.getAllLeaveApplications();
    }

    @GetMapping("/leave/{leaveId}")
    public LeaveManagementDTO getLeaveByLeaveId(@PathVariable Long leaveId) {
        return adminService.getLeaveApplicationByLeaveId(leaveId);
    }

    @PutMapping("/leave/{leaveId}/leaveStatus")
    public LeaveManagementDTO updateLeaveStatus(
            @PathVariable Long leaveId,
            @RequestParam LeaveApplicationStatus leaveStatus) {
        return adminService.updateLeaveStatus(leaveId, leaveStatus);
    }

    @GetMapping("/leave-balance/user/{userId}")
    public ResponseEntity<LeaveBalanceDTO> getLeaveBalance(@PathVariable Long userId) {
        return ResponseEntity.ok(adminService.getLeaveBalanceByUserId(userId));
    }

    @GetMapping("/leave/status/{status}")
    public List<LeaveManagementDTO> getLeavesByStatus(@PathVariable LeaveApplicationStatus status) {
        return adminService.getLeaveApplicationByStatus(status);
    }

    @GetMapping("/leave/range")
    public List<LeaveManagementDTO> getLeavesByDateRange(
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd") Date startDate,
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd") Date endDate) {
        return adminService.getLeaveApplicationByDateRange(startDate, endDate);
    }

    @GetMapping("/leave/status-count")
    public Map<LeaveApplicationStatus, Long> getLeaveCountByStatus() {
        return adminService.countLeaveApplicationByStatus();
    }
}


