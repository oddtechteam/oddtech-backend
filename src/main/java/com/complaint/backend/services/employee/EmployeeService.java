package com.complaint.backend.services.employee;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import com.complaint.backend.entities.User;
import com.complaint.backend.dtos.CommentDTO;
import com.complaint.backend.dtos.LeaveBalanceDTO;
import com.complaint.backend.dtos.LeaveManagementDTO;
import com.complaint.backend.dtos.TaskDTO;
import com.complaint.backend.entities.LeaveManagement;
import com.complaint.backend.enums.LeaveApplicationStatus;
import com.complaint.backend.repositories.LeaveBalanceRepository;
import com.complaint.backend.repositories.LeaveManagementRepository;

public interface EmployeeService {

    List<TaskDTO> getTasksByUserId(Long id);

    TaskDTO updateTask(Long id, String status);

    TaskDTO getTaskById(Long id);

    CommentDTO createComment(Long taskId, Long postedBy, String content);

    List<CommentDTO> getCommentsByTask(Long taskId);




    // employee service for leave management;



    public List<LeaveManagementDTO> getAllLeavesByUser(Long userId);
    public Long countLeavesByUserAndStatus(Long userId, LeaveApplicationStatus leaveStatus);
    public List<LeaveManagementDTO> getLeavesByUserAndLeaveType(Long userId, String leaveType);
    public List<LeaveManagementDTO> getLeavesByUserAndDateRange(Long userId, Date start, Date end);
    public List<LeaveManagementDTO> getLeavesByStatus(LeaveApplicationStatus leaveStatus);
    public Long countAllLeavesByStatus(LeaveApplicationStatus leaveStatus);
    public List<LeaveManagementDTO> getAllLeavesInDateRange(Date startDate, Date endDate);
    public LeaveManagementDTO createLeave(LeaveManagementDTO dto);

    public LeaveBalanceDTO getLeaveBalanceByUserId(Long userId);

    List<User> getAllEmployees();
    User getEmployeeById(Long id);
//	private LeaveManagementDTO toDTO(LeaveManagement entity) {
//		LeaveManagementDTO dto = new LeaveManagementDTO();
//		dto.setLeaveId(entity.getLeaveId());
//		dto.setStartDate(entity.getStartDate());
//		dto.setEndDate(entity.getEndDate());
//		dto.setReason(entity.getReason());
//		dto.setLeaveType(entity.getLeaveType());
//		dto.setLeaveStatus(entity.getLeaveStatus());
//
//
//
//		return dto;
//	}

//  if (entity.getUser() != null) {
//  dto.setEmployeeId(entity.getUser().userId());
//  dto.setEmployeeName(entity.getUser().getUsername());
//}
}
