package com.complaint.backend.controllers;



import com.complaint.backend.entities.PlanningTask;
import  com.complaint.backend.services.PlanningTaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/tasks")
@CrossOrigin(origins = "http://localhost:5173") // Allow frontend access
public class PlanningTaskController {

    @Autowired
    private PlanningTaskService taskService;

    @GetMapping
    public List<PlanningTask> getAllTasks() {
        return taskService.getAllTasks();
    }

    @PostMapping
    public PlanningTask createTask(@RequestBody PlanningTask task) {
        return taskService.createTask(task);
    }

    @PutMapping("/{id}")
    public PlanningTask updateTask(@PathVariable Long id, @RequestBody PlanningTask taskDetails) {
        return taskService.updateTask(id, taskDetails);
    }

    @DeleteMapping("/{id}")
    public void deleteTask(@PathVariable Long id) {
        taskService.deleteTask(id);
    }
}