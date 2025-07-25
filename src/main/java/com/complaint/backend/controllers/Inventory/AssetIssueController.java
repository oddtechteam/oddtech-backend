package com.complaint.backend.controllers.Inventory;

import com.complaint.backend.dtos.AssetIssueDTO;
import com.complaint.backend.entities.AssetIssue;
import com.complaint.backend.services.Inventory.AssetIssueService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/issues")
@CrossOrigin(origins = "http://localhost:5173")
public class AssetIssueController {

    private final AssetIssueService issueService;

    @Autowired
    public AssetIssueController(AssetIssueService issueService) {
        this.issueService = issueService;
    }

    @PostMapping
    public ResponseEntity<AssetIssue> createIssue(@RequestBody AssetIssueDTO issueDTO) {
        AssetIssue created = issueService.createIssue(issueDTO);
        return ResponseEntity.ok(created);
    }

    @GetMapping("/open")
    public ResponseEntity<List<AssetIssue>> getOpenIssues() {
        return ResponseEntity.ok(issueService.getOpenIssues());
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<AssetIssue> updateIssueStatus(
            @PathVariable Long id,
            @RequestParam String status,
            @RequestParam(required = false) String resolution) {
        AssetIssue updated = issueService.updateIssueStatus(id, status, resolution);
        return ResponseEntity.ok(updated);
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<AssetIssue>> getIssuesByUser(@PathVariable Long userId) {
        return ResponseEntity.ok(issueService.getIssuesByUser(userId));
    }
}