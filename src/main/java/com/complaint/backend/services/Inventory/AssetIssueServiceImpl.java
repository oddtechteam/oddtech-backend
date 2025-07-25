package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetIssueDTO;
import com.complaint.backend.entities.Asset;
import com.complaint.backend.entities.AssetIssue;
import com.complaint.backend.entities.User;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.AssetIssueRepository;
import com.complaint.backend.repositories.AssetRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

@Service
public class AssetIssueServiceImpl implements AssetIssueService {

    private final AssetIssueRepository issueRepository;
    private final AssetRepository assetRepository;
    private final UserRepository userRepository;

    @Autowired
    public AssetIssueServiceImpl(AssetIssueRepository issueRepository,
                                 AssetRepository assetRepository,
                                 UserRepository userRepository) {
        this.issueRepository = issueRepository;
        this.assetRepository = assetRepository;
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public AssetIssue createIssue(AssetIssueDTO issueDTO) {
        // Validate and fetch asset
        Asset asset = assetRepository.findById(issueDTO.getAssetId())
                .orElseThrow(() -> new ResourceNotFoundException("Asset not found with id: " + issueDTO.getAssetId()));

        // Validate and fetch reporting user
        User reportedBy = userRepository.findById(issueDTO.getReportedById())
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + issueDTO.getReportedById()));

        // Create and save new issue
        AssetIssue issue = new AssetIssue();
        issue.setAsset(asset);
        issue.setReportedBy(reportedBy);
        issue.setIssueType(issueDTO.getIssueType());
        issue.setDescription(issueDTO.getDescription());
        issue.setStepsToReproduce(issueDTO.getStepsToReproduce());
        issue.setPriority(issueDTO.getPriority());
        issue.setStatus("OPEN");
        issue.setReportedDate(new Date());

        return issueRepository.save(issue);
    }

    @Override
    @Transactional
    public AssetIssue updateIssueStatus(Long id, String status, String resolution) {
        AssetIssue issue = issueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Issue not found with id: " + id));

        // Update status and resolution
        issue.setStatus(status);
        issue.setResolution(resolution);

        // Set resolved date if status is RESOLVED
        if ("RESOLVED".equals(status)) {
            issue.setResolvedDate(new Date());
        }

        return issueRepository.save(issue);
    }

    @Override
    public List<AssetIssue> getOpenIssues() {
        // Changed from findByStatus("OPEN") to use the JOIN FETCH query
        return issueRepository.findOpenIssuesWithDetails();
    }
    @Override
    public List<AssetIssue> getIssuesByUser(Long userId) {
        return issueRepository.findByReportedById(userId);
    }
}