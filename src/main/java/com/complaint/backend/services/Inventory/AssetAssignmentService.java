package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetAssignmentDTO;
import com.complaint.backend.entities.AssetAssignment;
import java.util.List;

public interface AssetAssignmentService {
    AssetAssignment createAssignment(AssetAssignmentDTO assignmentDTO);  // Changed parameter type
    List<AssetAssignment> getAllAssignments();
    AssetAssignment getAssignmentById(Long id);
    AssetAssignment updateAssignment(Long id, AssetAssignment assignment);
    void deleteAssignment(Long id);
    List<AssetAssignment> getAssignmentsByEmployee(Long employeeId);
    List<AssetAssignment> getActiveAssignments();
    List<AssetAssignment> getActiveAssignmentsWithDetails();
    List<AssetAssignment> getPendingReturns();
    AssetAssignment processReturn(Long id, String condition, String notes);
    List<AssetAssignment> getAssignmentsByEmployeeId(Long employeeId);
}