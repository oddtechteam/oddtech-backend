package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetAssignmentDTO;
import com.complaint.backend.entities.Asset;
import com.complaint.backend.entities.AssetAssignment;
import com.complaint.backend.entities.User;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.AssetAssignmentRepository;
import com.complaint.backend.repositories.AssetRepository;
import com.complaint.backend.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class AssetAssignmentServiceImpl implements AssetAssignmentService {

    @Autowired
    private AssetAssignmentRepository assignmentRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private UserRepository userRepository;
    public AssetAssignmentServiceImpl(AssetAssignmentRepository assignmentRepository,
                                      UserRepository userRepository,
                                      AssetRepository assetRepository) {
        this.assignmentRepository = assignmentRepository;
        this.userRepository = userRepository;
        this.assetRepository = assetRepository;
    }

    @Override
    public List<AssetAssignment> getActiveAssignmentsWithDetails() {
        return assignmentRepository.findActiveAssignmentsWithDetails();
    }

    @Override
    public AssetAssignment createAssignment(AssetAssignmentDTO assignmentDTO) {
        User employee = userRepository.findById(assignmentDTO.getEmployeeId())
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        Asset asset = assetRepository.findById(assignmentDTO.getAssetId())
                .orElseThrow(() -> new ResourceNotFoundException("Asset not found"));

        AssetAssignment assignment = new AssetAssignment();
        assignment.setEmployee(employee);
        assignment.setAsset(asset);
        assignment.setAssignmentDate(assignmentDTO.getAssignmentDate());
        assignment.setExpectedReturnDate(assignmentDTO.getExpectedReturnDate());
        assignment.setNotes(assignmentDTO.getNotes());
        assignment.setStatus(assignmentDTO.getStatus() != null ? assignmentDTO.getStatus() : "Active");

        asset.setAssetCondition("Assigned");
        assetRepository.save(asset);

        return assignmentRepository.save(assignment);
    }

    @Override
    public List<AssetAssignment> getAllAssignments() {
        return assignmentRepository.findAll();
    }

    @Override
    public AssetAssignment getAssignmentById(Long id) {
        return assignmentRepository.findById(id).orElse(null);
    }

    @Override
    public AssetAssignment updateAssignment(Long id, AssetAssignment updatedAssignment) {
        Optional<AssetAssignment> optionalAssignment = assignmentRepository.findById(id);
        if (optionalAssignment.isPresent()) {
            AssetAssignment assignment = optionalAssignment.get();
            assignment.setNotes(updatedAssignment.getNotes());
            assignment.setExpectedReturnDate(updatedAssignment.getExpectedReturnDate());
            assignment.setStatus(updatedAssignment.getStatus());
            return assignmentRepository.save(assignment);
        }
        return null;
    }

    @Override
    public List<AssetAssignment> getPendingReturns() {
        return assignmentRepository.findByStatusAndActualReturnDateIsNull("ACTIVE");
    }

//    @Override
//    public List<AssetAssignment> getPendingReturns() {
//        return assignmentRepository.findPendingReturnsWithDetails();
//    }

    @Override
    @Transactional
    public AssetAssignment processReturn(Long id, String condition, String notes) {
        return assignmentRepository.findById(id)
                .map(assignment -> {
                    // Verify assignment is active
                    if (!"ACTIVE".equals(assignment.getStatus())) {
                        throw new SecurityException("Assignment is not active");
                    }

                    // Update assignment
                    assignment.setStatus("RETURNED");
                    assignment.setActualReturnDate(new Date());
                    assignment.setNotes(notes);

                    // Update asset condition
                    Asset asset = assignment.getAsset();
                    asset.setAssetCondition(condition);
                    assetRepository.save(asset);

                    return assignmentRepository.save(assignment);
                })
                .orElseThrow(() -> new ResourceNotFoundException("Assignment not found"));
    }

    @Override
    public void deleteAssignment(Long id) {
        assignmentRepository.deleteById(id);
    }

    @Override
    public List<AssetAssignment> getAssignmentsByEmployee(Long employeeId) {
        // Use the method that fetches all assignments with assets, not just active ones
        return assignmentRepository.findByEmployeeIdWithAsset(employeeId);
    }

    public List<AssetAssignment> getAssignmentsByEmployeeId(Long employeeId) {
        return assignmentRepository.findByEmployeeId(employeeId);
    }



    @Override
    public List<AssetAssignment> getActiveAssignments() {
        return assignmentRepository.findByStatus("ACTIVE");
    }


}