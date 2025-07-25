package com.complaint.backend.services.employee;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.complaint.backend.dtos.CommentDTO;
import com.complaint.backend.dtos.LeaveBalanceDTO;
import com.complaint.backend.dtos.LeaveManagementDTO;
import com.complaint.backend.dtos.TaskDTO;
import com.complaint.backend.entities.Comment;
import com.complaint.backend.entities.LeaveBalance;
import com.complaint.backend.entities.LeaveManagement;
import com.complaint.backend.entities.Task;
import com.complaint.backend.entities.User;
import com.complaint.backend.enums.LeaveApplicationStatus;
import com.complaint.backend.enums.TaskStatus;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.CommentRepository;
import com.complaint.backend.repositories.LeaveBalanceRepository;
import com.complaint.backend.repositories.LeaveManagementRepository;
import com.complaint.backend.repositories.TaskRepository;
import com.complaint.backend.repositories.UserRepository;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor

public class EmployeeServieImpl implements EmployeeService {

    private final TaskRepository taskRepository;
    private final UserRepository userRepository;
    private final CommentRepository commentRepository;

    @Override
    public List<TaskDTO> getTasksByUserId(Long id) {
        return taskRepository.findAllByUserId(id).stream().map(Task::getTaskDTO).collect(Collectors.toList());
    }

    @Override
    public TaskDTO updateTask(Long id, String status) {
        Optional<Task> optionalTask = taskRepository.findById(id);
        if (optionalTask.isPresent()) {
            Task existingTask = optionalTask.get();
            TaskStatus taskStatus = mapStringToTaskStatus(String.valueOf(status));
            existingTask.setTaskStatus(taskStatus);
            return taskRepository.save(existingTask).getTaskDTO();

        }

        return null;

    }
    @Override
    public List<User> getAllEmployees() {
        return userRepository.findAll();
    }

    @Override
    public User getEmployeeById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found with id: " + id));
    }
    private TaskStatus mapStringToTaskStatus(String taskStatus) {
        return switch (taskStatus) {
            case "PENDING" -> TaskStatus.PENDING;
            case "INPROGRESS" -> TaskStatus.INPROGRESS;
            case "COMPLETED" -> TaskStatus.COMPLETED;
            case "DEFERRED" -> TaskStatus.DEFERRED;
            default -> TaskStatus.CANCELLED;

        };

    }

    @Override
    public TaskDTO getTaskById(Long id) {
        return taskRepository.findById(id).map(Task::getTaskDTO).orElse(null);

    }

    @Override
    public CommentDTO createComment(Long taskld, Long postedBy, String content) {
        Optional<Task> optionalTask = taskRepository.findById(taskld);
        Optional<User> optionalUser = userRepository.findById(postedBy);
        if (optionalUser.isPresent() && optionalTask.isPresent()) {
            Comment comment = new Comment();
            comment.setContent(content);
            comment.setCreatedAt(new Date());
            comment.setUser(optionalUser.get());
            comment.setTask(optionalTask.get());
            return commentRepository.save(comment).getCommentDTO();

        }
        throw new EntityNotFoundException("Task or user not found! ");

    }

    @Override
    public List<CommentDTO> getCommentsByTask(Long taskId) {
        return commentRepository.findAllByTaskId(taskId).stream().map(Comment::getCommentDTO).collect(Collectors.toList());
    }






    //employee service implementation for leave management



    @Autowired
    private LeaveManagementRepository leaveManagementRepository;

    @Override
    public List<LeaveManagementDTO> getAllLeavesByUser(Long userId) {
        return leaveManagementRepository.findByUserId(userId)
                .stream().map(this::toDTO).collect(Collectors.toList());
    }

    @Override
    public Long countLeavesByUserAndStatus(Long userId, LeaveApplicationStatus status) {
        return leaveManagementRepository.countByUserIdAndLeaveStatus(userId, status);
    }

    @Override
    public List<LeaveManagementDTO> getLeavesByUserAndLeaveType(Long userId, String leaveType) {
        return leaveManagementRepository.findByUserIdAndLeaveType(userId, leaveType)
                .stream().map(this::toDTO).collect(Collectors.toList());
    }

    @Override
    public List<LeaveManagementDTO> getLeavesByUserAndDateRange(Long userId, Date start, Date end) {
        return leaveManagementRepository.findByUserIdAndStartDateBetween(userId, start, end)
                .stream().map(this::toDTO).collect(Collectors.toList());
    }

    @Override
    public List<LeaveManagementDTO> getLeavesByStatus(LeaveApplicationStatus status) {
        return leaveManagementRepository.findByLeaveStatus(status)
                .stream().map(this::toDTO).collect(Collectors.toList());
    }

    @Override
    public Long countAllLeavesByStatus(LeaveApplicationStatus status) {
        return leaveManagementRepository.countByLeaveStatus(status);
    }

    @Override
    public List<LeaveManagementDTO> getAllLeavesInDateRange(Date startDate, Date endDate) {
        return leaveManagementRepository.findByStartDateBetween(startDate, endDate)
                .stream().map(this::toDTO).collect(Collectors.toList());
    }

    // ✅ DTO Converter
    private LeaveManagementDTO toDTO(LeaveManagement entity) {
        LeaveManagementDTO dto = new LeaveManagementDTO();
        dto.setUserId(entity.getUser().getId());
        dto.setLeaveId(entity.getLeaveId()); // assuming it's named leaveId, not id
        dto.setStartDate(entity.getStartDate());
        dto.setEndDate(entity.getEndDate());
        dto.setReason(entity.getReason());
        dto.setLeaveType(entity.getLeaveType());
        dto.setLeaveStatus(entity.getLeaveStatus());
        return dto;
    }


    public LeaveManagementDTO createLeave(LeaveManagementDTO dto) {
        LeaveManagement entity = new LeaveManagement();
        entity.setLeaveType(dto.getLeaveType());
        entity.setStartDate(dto.getStartDate());
        entity.setEndDate(dto.getEndDate());
        entity.setReason(dto.getReason());

        // If you have a User relationship, fetch the user by ID
        User user = userRepository.findById(dto.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        entity.setUser(user);

        entity.setLeaveStatus(LeaveApplicationStatus.PENDING); // Default

        LeaveManagement saved = leaveManagementRepository.save(entity);

        return toDTO(saved);
    }




    //leave balance

    @Autowired
    private LeaveBalanceRepository leaveBalanceRepository;
    @Override
    public LeaveBalanceDTO getLeaveBalanceByUserId(Long userId) {
        LeaveBalance balance = leaveBalanceRepository.findByUserId(userId);

        if (balance == null) {
            throw new ResourceNotFoundException("Leave balance not found for user ID: " + userId);
        }

        LeaveBalanceDTO dto = new LeaveBalanceDTO();
        dto.setUserId(userId);
        dto.setAnnualLeave(balance.getAnnualLeave());
        dto.setCasualLeave(balance.getCasualLeave());
        dto.setSickLeave(balance.getSickLeave());
        dto.setEarnedLeave(balance.getEarnedLeave());

        return dto;
    }


}
