package com.complaint.backend.services.admin;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.complaint.backend.dtos.CommentDTO;
import com.complaint.backend.dtos.LeaveBalanceDTO;
import com.complaint.backend.dtos.LeaveManagementDTO;
import com.complaint.backend.dtos.TaskDTO;
import com.complaint.backend.dtos.UserDTO;
import com.complaint.backend.entities.Comment;
import com.complaint.backend.entities.LeaveBalance;
import com.complaint.backend.entities.LeaveManagement;
import com.complaint.backend.entities.Task;
import com.complaint.backend.entities.User;
import com.complaint.backend.enums.LeaveApplicationStatus;
import com.complaint.backend.enums.TaskStatus;
import com.complaint.backend.enums.UserRole;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.CommentRepository;
import com.complaint.backend.repositories.LeaveBalanceRepository;
import com.complaint.backend.repositories.LeaveManagementRepository;
import com.complaint.backend.repositories.TaskRepository;
import com.complaint.backend.repositories.UserRepository;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {
   private final UserRepository userRepository;

   private final TaskRepository taskRepository;

   private final CommentRepository commentRepository;

   private final LeaveManagementRepository leaveManagementRepository;
   private final LeaveBalanceRepository leaveBalanceRepository;

   @Override
   public List<UserDTO> getUsers() {
      return userRepository.findAll()
              .stream()
              .filter(user -> user.getUserRole() == UserRole.EMPLOYEE)
              .map(User::getUserDTO)
              .collect(Collectors.toList());

   }

   @Override
   public TaskDTO postTask(TaskDTO taskDTO) {
      Optional<User> optionalUser = userRepository.findById(taskDTO.getEmployeeId());

      if (optionalUser.isPresent()) {
         Task task = new Task();
         task.setTitle(taskDTO.getTitle());
         task.setDescription(taskDTO.getDescription());
         task.setPriority(taskDTO.getPriority());
         task.setStartDate(taskDTO.getStartDate());
         task.setDueDate(taskDTO.getDueDate());
         task.setUser(optionalUser.get());
         task.setTaskStatus(TaskStatus.PENDING);
         return taskRepository.save(task).getTaskDTO();

      }
      return taskDTO;

   }

   @Override
   public List<TaskDTO> getTasks() {
      return taskRepository.findAll().stream().map(Task::getTaskDTO).collect(Collectors.toList());
   }

   @Override
   public TaskDTO getTaskById(Long id) {
      Optional<Task> optionalTask = taskRepository.findById(id);
      return optionalTask.map(Task::getTaskDTO).orElse(null);
   }

   @Override
   public void deleteTask(Long id) {
      taskRepository.deleteById(id);
   }

   @Override
   public List<TaskDTO> searchTask(String title) {
      return taskRepository.findAllByTitleContaining(title).stream().map(Task::getTaskDTO).collect(Collectors.toList());
   }

   @Override
   public TaskDTO updateTask(Long id, TaskDTO taskDTO) {
      Optional<Task> optionalTask = taskRepository.findById(id);
      Optional<User> optionalUser = userRepository.findById(taskDTO.getEmployeeId());
      if (optionalTask.isPresent() && optionalUser.isPresent()) {

         Task existingTask = optionalTask.get();
         existingTask.setTitle(taskDTO.getTitle());
         existingTask.setDescription(taskDTO.getDescription());
         existingTask.setDueDate(taskDTO.getDueDate());
         existingTask.setPriority(taskDTO.getPriority());
         existingTask.setUser(optionalUser.get());
         TaskStatus taskStatus = mapStringToTaskStatus(String.valueOf(taskDTO.getTaskStatus()));
         existingTask.setTaskStatus(taskStatus);
         return taskRepository.save(existingTask).getTaskDTO();

      }

      return null;

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
   public CommentDTO createComment(Long taskld, Long postedBy, String content) {
      Optional<Task> optionalTask =  taskRepository.findById(taskld) ;
      Optional<User> optionalUser = userRepository. findById(postedBy);
      if (optionalUser.isPresent() && optionalTask.isPresent()){
         Comment comment = new Comment();
         comment.setContent(content);
         comment.setCreatedAt(new Date());
         comment.setUser(optionalUser.get()) ;
         comment.setTask(optionalTask.get()) ;
         return commentRepository.save(comment).getCommentDTO();

      }
      throw new EntityNotFoundException("Task or user not found! " ) ;
   }

   @Override
   public List<CommentDTO> getCommentsByTask(Long taskId) {
      return commentRepository.findAllByTaskId(taskId).stream().map(Comment::getCommentDTO).collect(Collectors.toList());
   }



   // Leave management service implementation

//   private LeaveManagementDTO toDTO(LeaveManagement entity) {
//       LeaveManagementDTO dto = new LeaveManagementDTO();
//       dto.setLeaveId(entity.getLeaveId());
//       dto.setStartDate(entity.getStartDate());
//       dto.setEndDate(entity.getEndDate());
//       dto.setReason(entity.getReason());
//       dto.setLeaveStatus(entity.getLeaveStatus());
//       dto.setLeaveType(entity.getLeaveType());
//       return dto;
//   }
//


   private LeaveManagementDTO toDTO(LeaveManagement entity) {
      LeaveManagementDTO dto = new LeaveManagementDTO();
      dto.setLeaveId(entity.getLeaveId());
      dto.setStartDate(entity.getStartDate());
      dto.setEndDate(entity.getEndDate());
      dto.setReason(entity.getReason());
      dto.setLeaveType(entity.getLeaveType());
      dto.setLeaveStatus(entity.getLeaveStatus()); // Convert enum to string

      // Set the user name as employee
      if (entity.getUser() != null) {
         dto.setUserId(entity.getUser().getId());
         dto.setUserName(entity.getUser().getName());
      } else {
         dto.setUserId(null);
         dto.setUserName("Unknown");
      }

      return dto;
   }


   @Override
   public List<LeaveManagementDTO> getAllLeaveApplications() {
      return leaveManagementRepository.findAll().stream()
              .map(this::toDTO)
              .collect(Collectors.toList());
   }

   @Override
   public LeaveManagementDTO getLeaveApplicationByLeaveId(Long leaveId) {
      LeaveManagement leave = leaveManagementRepository.findById(leaveId)
              .orElseThrow(() -> new RuntimeException("Leave application not found with ID: " + leaveId));
      return toDTO(leave);
   }

   @Override
   public LeaveManagementDTO approveLeave(Long leaveId, LeaveApplicationStatus leaveStatus) {
      LeaveManagement leave = leaveManagementRepository.findById(leaveId)
              .orElseThrow(() -> new RuntimeException("Leave application not found with ID: " + leaveId));
      leave.setLeaveStatus(LeaveApplicationStatus.APPROVED);
      return toDTO(leaveManagementRepository.save(leave));
   }

   @Override
   public LeaveManagementDTO rejectleave(Long leaveId, LeaveApplicationStatus leaveStatus) {
      LeaveManagement leave = leaveManagementRepository.findById(leaveId)
              .orElseThrow(() -> new RuntimeException("Leave application not found with ID: " + leaveId));
      leave.setLeaveStatus(LeaveApplicationStatus.REJECTED);
      return toDTO(leaveManagementRepository.save(leave));
   }

   @Override
   public List<LeaveManagementDTO> getLeaveApplicationByStatus(LeaveApplicationStatus leaveStatus) {
      return leaveManagementRepository.findByLeaveStatus(leaveStatus).stream()
              .map(this::toDTO)
              .collect(Collectors.toList());
   }



   @Override
   public List<LeaveManagementDTO> getLeaveApplicationByDateRange(Date startDate, Date endDate) {
      return leaveManagementRepository.findByStartDateBetween(startDate, endDate).stream()
              .map(this::toDTO)
              .collect(Collectors.toList());
   }

   @Override
   public Map<LeaveApplicationStatus, Long> countLeaveApplicationByStatus() {
      List<LeaveManagement> all = leaveManagementRepository.findAll();
      return all.stream()
              .collect(Collectors.groupingBy(
                      LeaveManagement::getLeaveStatus,
                      Collectors.counting()
              ));
   }


   // working code for aproval and rejection

//   @Override
//   public LeaveManagementDTO updateLeaveStatus(Long leaveId, LeaveApplicationStatus leaveStatus) {
//       LeaveManagement leave = leaveManagementRepository.findById(leaveId)
//               .orElseThrow(() -> new ResourceNotFoundException("Leave not found with ID: " + leaveId));
//
//       leave.setLeaveStatus(leaveStatus);
//       LeaveManagement updatedLeave = leaveManagementRepository.save(leave);
//
//       return toDTO(updatedLeave);
//   }






   // new code for aproved with update leave balance



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

   @Override
   @Transactional
   public LeaveManagementDTO updateLeaveStatus(Long leaveId, LeaveApplicationStatus leaveStatus) {
      LeaveManagement leave = leaveManagementRepository.findById(leaveId)
              .orElseThrow(() -> new ResourceNotFoundException("Leave not found with ID: " + leaveId));

      // Only process balance deduction on APPROVAL
      if (leaveStatus == LeaveApplicationStatus.APPROVED && leave.getLeaveStatus() != LeaveApplicationStatus.APPROVED) {
         User user = leave.getUser(); // assuming LeaveManagement has a User reference
         LeaveBalance balance = leaveBalanceRepository.findByUserId(user.getId());
         long diffInMillies = leave.getEndDate().getTime() - leave.getStartDate().getTime();
         long days = TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS) + 1;

         String leaveType = leave.getLeaveType() == null ? "" : leave.getLeaveType().trim().toUpperCase();
         System.out.println("Leave Type Received: '" + leave.getLeaveType() + "'");
         System.out.println("Transformed: '" + leave.getLeaveType().trim().toUpperCase() + "'");

         switch (leaveType) {
            case "ANNUAL":
               if (balance.getAnnualLeave() < days)
                  throw new RuntimeException("Not enough anual leaves.");
               balance.setAnnualLeave(balance.getAnnualLeave() - (int) days);
               break;
            case "CASUAL":
               if (balance.getCasualLeave() < days)
                  throw new RuntimeException("Not enough casual leaves.");
               balance.setCasualLeave(balance.getCasualLeave() - (int) days);
               break;
            case "SICK":
               if (balance.getSickLeave() < days)
                  throw new RuntimeException("Not enough sick leaves.");
               balance.setSickLeave(balance.getSickLeave() - (int) days);
               break;
            case "EARNED":
               if (balance.getEarnedLeave() < days)
                  throw new RuntimeException("Not enough earned leaves.");
               balance.setEarnedLeave(balance.getEarnedLeave() - (int) days);
               break;
            default:
               throw new RuntimeException("Invalid leave type.");
         }

         leaveBalanceRepository.save(balance);
      }

      leave.setLeaveStatus(leaveStatus);
      LeaveManagement updatedLeave = leaveManagementRepository.save(leave);
      return toDTO(updatedLeave);
   }



   // fetching leave balance






}