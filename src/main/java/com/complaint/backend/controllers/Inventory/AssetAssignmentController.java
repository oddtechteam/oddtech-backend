package com.complaint.backend.controllers.Inventory;

import com.complaint.backend.dtos.AssetAssignmentDTO;
import com.complaint.backend.dtos.AssetRequestDTO;
import com.complaint.backend.entities.Asset;
import com.complaint.backend.entities.AssetAssignment;
import com.complaint.backend.entities.AssetRequest;
import com.complaint.backend.entities.User;
import com.complaint.backend.services.Inventory.AssetAssignmentService;
import com.complaint.backend.services.Inventory.AssetRequestService;
import com.complaint.backend.services.Inventory.AssetService;
import com.complaint.backend.services.employee.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/assignments")
@CrossOrigin(origins = "http://localhost:5173")
public class AssetAssignmentController {

    private final AssetAssignmentService assignmentService;
    private final AssetService assetService;
    private final AssetRequestService requestService;
    private final EmployeeService employeeService;

    @Autowired
    public AssetAssignmentController(AssetAssignmentService assignmentService,
                                     AssetService assetService,
                                     AssetRequestService requestService,
                                     EmployeeService employeeService) {
        this.assignmentService = assignmentService;
        this.assetService = assetService;
        this.requestService = requestService;
        this.employeeService = employeeService;
    }

    @PostMapping
    public ResponseEntity<AssetAssignment> createAssignment(@RequestBody AssetAssignmentDTO assignmentDTO) {
        AssetAssignment created = assignmentService.createAssignment(assignmentDTO);
        return ResponseEntity.ok(created);
    }

    @GetMapping
    public List<AssetAssignment> getAllAssignments() {
        return assignmentService.getAllAssignments();
    }
    @GetMapping("/assets")
    public ResponseEntity<List<Asset>> getAllAssets() {
        return ResponseEntity.ok(assetService.getAllAssets());
    }

    @GetMapping("/employees")
    public ResponseEntity<List<User>> getAllEmployees() {
        return ResponseEntity.ok(employeeService.getAllEmployees());
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssetAssignment> getAssignmentById(@PathVariable Long id) {
        AssetAssignment assignment = assignmentService.getAssignmentById(id);
        return assignment != null ? ResponseEntity.ok(assignment) : ResponseEntity.notFound().build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<AssetAssignment> updateAssignment(@PathVariable Long id, @RequestBody AssetAssignment assignment) {
        AssetAssignment updated = assignmentService.updateAssignment(id, assignment);
        return updated != null ? ResponseEntity.ok(updated) : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAssignment(@PathVariable Long id) {
        assignmentService.deleteAssignment(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/employee/{employeeId}")
    public ResponseEntity<List<AssetAssignment>> getAssignmentsByEmployeeId(@PathVariable Long employeeId) {
        List<AssetAssignment> assignments = assignmentService.getAssignmentsByEmployeeId(employeeId);
        return ResponseEntity.ok(assignments);
    }


    @GetMapping("/active")
    public List<AssetAssignment> getActiveAssignments() {
        return assignmentService.getActiveAssignments();
    }

    @PutMapping("/{id}/condition")
    public ResponseEntity<Asset> updateAssetCondition(
            @PathVariable Long id,
            @RequestParam String condition,
            @RequestBody(required = false) Map<String, String> requestBody) {

        String notes = requestBody != null ? requestBody.get("notes") : null;
        Asset updated = assetService.updateAssetCondition(id, condition, notes);
        return updated != null ? ResponseEntity.ok(updated) : ResponseEntity.notFound().build();
    }

    @GetMapping("/returns/pending")
    public ResponseEntity<List<AssetAssignment>> getPendingReturns() {
        List<AssetAssignment> pendingReturns = assignmentService.getPendingReturns();
        return ResponseEntity.ok(pendingReturns);
    }

    @PutMapping("/{id}/return")
    public ResponseEntity<?> processReturn(
            @PathVariable Long id,
            @RequestParam String condition,
            @RequestBody(required = false) Map<String, String> body,
            @RequestHeader("Authorization") String authHeader) {

        try {
            // Validate condition
            if (!List.of("Available", "Maintenance", "Damaged").contains(condition)) {
                return ResponseEntity.badRequest().body("Invalid condition specified");
            }

            String notes = body != null ? body.get("notes") : null;
            AssetAssignment processed = assignmentService.processReturn(id, condition, notes);

            if (processed == null) {
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok(processed);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing return");
        }
    }

    @PostMapping("/request")
    public ResponseEntity<AssetRequest> createAssetRequest(@RequestBody AssetRequestDTO requestDTO) {
        AssetRequest request = requestService.createRequest(requestDTO);
        return ResponseEntity.ok(request);
    }

    @GetMapping("/requests/pending")
    public ResponseEntity<List<AssetRequest>> getPendingRequests() {
        List<AssetRequest> requests = requestService.getPendingRequestsWithDetails();
        System.out.println("Returning " + requests.size() + " pending requests");
        return ResponseEntity.ok(requests);
    }

    @PutMapping("/requests/{id}/approve")
    public ResponseEntity<AssetAssignment> approveRequest(@PathVariable Long id) {
        AssetAssignment assignment = requestService.approveRequest(id);
        return ResponseEntity.ok(assignment);
    }

    @PutMapping("/requests/{id}/reject")
    public ResponseEntity<AssetRequest> rejectRequest(@PathVariable Long id) {
        AssetRequest request = requestService.rejectRequest(id);
        return ResponseEntity.ok(request);
    }

    @GetMapping("/active-with-details")
    public ResponseEntity<List<AssetAssignment>> getActiveAssignmentsWithDetails() {
        List<AssetAssignment> assignments = assignmentService.getActiveAssignmentsWithDetails();
        return ResponseEntity.ok(assignments);
    }
}