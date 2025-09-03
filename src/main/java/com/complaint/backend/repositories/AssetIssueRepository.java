package com.complaint.backend.repositories;

import com.complaint.backend.entities.AssetIssue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface AssetIssueRepository extends JpaRepository<AssetIssue, Long> {
    List<AssetIssue> findByStatus(String status);
    List<AssetIssue> findByReportedById(Long userId);
    List<AssetIssue> findByAssetId(Long assetId);

    @Query("SELECT i FROM AssetIssue i JOIN FETCH i.asset JOIN FETCH i.reportedBy WHERE i.status = 'OPEN'")
    List<AssetIssue> findOpenIssuesWithDetails();
}