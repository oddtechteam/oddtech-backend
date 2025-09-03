package com.complaint.backend.repositories;

import com.complaint.backend.entities.Asset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assignments WHERE a.assetCondition != :condition")
    List<Asset> findByAssetConditionNot(@Param("condition") String condition);

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assignments aa LEFT JOIN FETCH aa.employee WHERE a.assetCondition = :condition")
    List<Asset> findByAssetConditionWithAssignments(@Param("condition") String condition);

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assignments aa LEFT JOIN FETCH aa.employee")
    List<Asset> findAllWithAssignments();

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assignments aa LEFT JOIN FETCH aa.employee WHERE a.id = :id")
    Optional<Asset> findByIdWithAssignments(@Param("id") Long id);

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assetRequests WHERE a.id = :id")
    Optional<Asset> findByIdWithAssetRequests(@Param("id") Long id);

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assignments aa LEFT JOIN FETCH aa.employee WHERE a.id = :id AND (aa IS NULL OR aa.status = 'ACTIVE')")
    Optional<Asset> findByIdWithActiveAssignments(@Param("id") Long id);

    @Query("SELECT a FROM Asset a LEFT JOIN FETCH a.assetRequests ar WHERE a.id = :id AND (ar IS NULL OR ar.status = 'PENDING')")
    Optional<Asset> findByIdWithPendingRequests(@Param("id") Long id);
}