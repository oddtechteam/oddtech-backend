package com.complaint.backend.repositories;

import com.complaint.backend.entities.AssetRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AssetRequestRepository extends JpaRepository<AssetRequest, Long> {
    List<AssetRequest> findByStatus(String status);
    List<AssetRequest> findByEmployeeId(Long employeeId);

    @Query(value = "SELECT * FROM asset_request WHERE status = 'PENDING'", nativeQuery = true)
    List<AssetRequest> findPendingRequestsNative(); // Raw SQL

    @Query("SELECT r FROM AssetRequest r " +
            "LEFT JOIN FETCH r.employee e " +
            "LEFT JOIN FETCH r.asset a " +
            "WHERE TRIM(r.status) = 'PENDING'")
    List<AssetRequest> findPendingRequestsWithDetails();

    @Modifying
    @Query("DELETE FROM AssetRequest ar WHERE ar.asset.id = :assetId")
    void deleteByAssetId(@Param("assetId") Long assetId);



}