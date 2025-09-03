// VisitorController.java
package com.complaint.backend.controllers.Visitor;

import com.complaint.backend.dtos.VisitorDto;
import com.complaint.backend.services.EntryGate.VisitorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/visitors")
public class VisitorController {

    @Autowired
    private VisitorService visitorService;

    @PostMapping
    public ResponseEntity<?> createVisitor(@RequestBody VisitorDto visitorDto) {
        try {
            VisitorDto createdVisitor = visitorService.createVisitor(visitorDto);
            return ResponseEntity.ok(createdVisitor);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Validation error",
                    "message", e.getMessage()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "Server error",
                    "message", e.getMessage(),
                    "rootCause", e.getCause() != null ? e.getCause().getMessage() : "N/A"
            ));
        }
    }

    @GetMapping("/getall")
    public ResponseEntity<List<VisitorDto>> getAllVisitors() {
        System.out.println("Fetching all visitors...");
        List<VisitorDto> visitors = visitorService.getAllVisitors();
        return ResponseEntity.ok(visitors);
    }

    @GetMapping("/{id}")
    public ResponseEntity<VisitorDto> getVisitorById(@PathVariable Long id) {
        VisitorDto visitor = visitorService.getVisitorById(id);
        return ResponseEntity.ok(visitor);
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<VisitorDto>> getVisitorsByStatus(@PathVariable String status) {
        List<VisitorDto> visitors = visitorService.getVisitorsByStatus(status);
        return ResponseEntity.ok(visitors);
    }

    @GetMapping("/search")
    public ResponseEntity<List<VisitorDto>> searchVisitors(@RequestParam String query) {
        List<VisitorDto> visitors = visitorService.searchVisitors(query);
        return ResponseEntity.ok(visitors);
    }

    @PutMapping("/{id}/approve")
    public ResponseEntity<VisitorDto> approveVisitor(@PathVariable Long id) {
        VisitorDto visitor = visitorService.approveVisitor(id);
        return ResponseEntity.ok(visitor);
    }

    @PutMapping("/{id}/reject")
    public ResponseEntity<VisitorDto> rejectVisitor(@PathVariable Long id) {
        VisitorDto visitor = visitorService.rejectVisitor(id);
        return ResponseEntity.ok(visitor);
    }

    @PutMapping("/{id}/entry")
    public ResponseEntity<VisitorDto> setEntryTime(@PathVariable Long id) {
        VisitorDto visitor = visitorService.setEntryTime(id);
        return ResponseEntity.ok(visitor);
    }

    @PutMapping("/{id}/exit")
    public ResponseEntity<VisitorDto> setExitTime(@PathVariable Long id) {
        VisitorDto visitor = visitorService.setExitTime(id);
        return ResponseEntity.ok(visitor);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteVisitor(@PathVariable Long id) {
        visitorService.deleteVisitor(id);
        return ResponseEntity.noContent().build();
    }
}