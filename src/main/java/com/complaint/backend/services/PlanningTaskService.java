package com.complaint.backend.services;



import com.complaint.backend.entities.PlanningTask;
import com.complaint.backend.repositories.PlanningTaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDate;
import java.util.List;

@Service
public class PlanningTaskService {

    @Autowired
    private PlanningTaskRepository taskRepository;

    public List<PlanningTask> getAllTasks() {
        return taskRepository.findAllByOrderByCreatedAtDesc();
    }

    public PlanningTask createTask(PlanningTask task) {
        task.setCreatedAt(LocalDate.now());
        return taskRepository.save(task);
    }

    public PlanningTask updateTask(Long id, PlanningTask taskDetails) {
        PlanningTask task = taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found"));
        
        task.setTitle(taskDetails.getTitle());
        task.setDescription(taskDetails.getDescription());
        task.setStatus(taskDetails.getStatus());
        task.setPriority(taskDetails.getPriority());
        task.setDueDate(taskDetails.getDueDate());
        
        return taskRepository.save(task);
    }

    public void deleteTask(Long id) {
        taskRepository.deleteById(id);
    }
}