package com.complaint.backend.services.admin;

import java.util.Date;
import java.util.List;
import java.util.Map;

import com.complaint.backend.dtos.CommentDTO;
import com.complaint.backend.dtos.LeaveBalanceDTO;
import com.complaint.backend.dtos.LeaveManagementDTO;
import com.complaint.backend.dtos.TaskDTO;
import com.complaint.backend.dtos.UserDTO;
import com.complaint.backend.entities.LeaveManagement;
import com.complaint.backend.enums.LeaveApplicationStatus;

public interface AdminService {

    List<UserDTO> getUsers();

    TaskDTO postTask(TaskDTO taskDTO);


    List<TaskDTO> getTasks();


    TaskDTO getTaskById(Long  id);


    void deleteTask(Long id);

    List<TaskDTO> searchTask(String title);

    TaskDTO updateTask(Long id, TaskDTO taskDTO);

    CommentDTO createComment(Long taskId, Long postedBy, String content);

    List<CommentDTO> getCommentsByTask(Long taskId);


    // Admin Service for Leave management

    List<LeaveManagementDTO>getAllLeaveApplications();
    LeaveManagementDTO getLeaveApplicationByLeaveId(Long leaveId);
    LeaveManagementDTO approveLeave(Long leaveId, LeaveApplicationStatus leaveStatus);
    LeaveManagementDTO rejectleave(Long leaveId, LeaveApplicationStatus leaveStatus);
    List<LeaveManagementDTO>getLeaveApplicationByStatus(LeaveApplicationStatus leaveStatus);
    List<LeaveManagementDTO>getLeaveApplicationByDateRange(Date startDate, Date endDate);
    Map<LeaveApplicationStatus,Long>countLeaveApplicationByStatus();

    public LeaveManagementDTO updateLeaveStatus(Long leaveId, LeaveApplicationStatus leaveStatus);
    LeaveBalanceDTO getLeaveBalanceByUserId(Long userId);




}
