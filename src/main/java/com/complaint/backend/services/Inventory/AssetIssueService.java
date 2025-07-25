package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetIssueDTO;
import com.complaint.backend.entities.AssetIssue;

import java.util.List;

public interface AssetIssueService {
    AssetIssue createIssue(AssetIssueDTO issueDTO);
    AssetIssue updateIssueStatus(Long id, String status, String resolution);
    List<AssetIssue> getOpenIssues();
    List<AssetIssue> getIssuesByUser(Long userId);
}