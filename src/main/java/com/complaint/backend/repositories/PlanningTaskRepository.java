package com.complaint.backend.repositories;



import com.complaint.backend.entities.PlanningTask;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PlanningTaskRepository extends JpaRepository<PlanningTask, Long> {
    List<PlanningTask> findAllByOrderByCreatedAtDesc();
}