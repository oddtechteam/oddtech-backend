package com.complaint.backend.services.Inventory;

import com.complaint.backend.entities.Asset;
import com.complaint.backend.repositories.AssetRepository;
import com.complaint.backend.repositories.AssetRequestRepository;
import com.complaint.backend.repositories.AssetRequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AssetServiceImpl implements AssetService {

    private final AssetRepository assetRepository;
    private final AssetRequestRepository assetRequestRepository;

    @Autowired
    public AssetServiceImpl(AssetRepository assetRepository, AssetRequestRepository assetRequestRepository) {
        this.assetRepository = assetRepository;
        this.assetRequestRepository = assetRequestRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public List<Asset> getAllAssets() {
        return assetRepository.findAllWithAssignments();
    }

    @Override
    @Transactional(readOnly = true)
    public Asset getAssetById(Long id) {
        return assetRepository.findByIdWithAssignments(id).orElse(null);
    }

    @Override
    @Transactional
    public Asset saveAsset(Asset asset) {
        if (asset.getAssetCondition() == null) {
            asset.setAssetCondition("Available");
        }
        return assetRepository.save(asset);
    }

    @Override
    @Transactional
    public Asset updateAsset(Long id, Asset updatedAsset) {
        return assetRepository.findById(id)
                .map(asset -> {
                    asset.setName(updatedAsset.getName());
                    asset.setType(updatedAsset.getType());
                    asset.setSerialNumber(updatedAsset.getSerialNumber());

                    if (updatedAsset.getAssetCondition() != null) {
                        asset.setAssetCondition(updatedAsset.getAssetCondition());
                    }

                    return assetRepository.save(asset);
                })
                .orElse(null);
    }



    @Override
    @Transactional
    public void deleteAsset(Long id) {
        Asset asset = assetRepository.findByIdWithAssetRequests(id)
                .orElseThrow(() -> new IllegalArgumentException("Asset not found"));

        // Optional: Auto-cancel pending requests
        asset.getAssetRequests().stream()
                .filter(request -> "PENDING".equals(request.getStatus()))
                .forEach(request -> request.setStatus("CANCELLED"));

        assetRepository.delete(asset);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Asset> getAvailableAssets() {
        return assetRepository.findByAssetConditionNot("Assigned");
    }

    @Override
    @Transactional
    public Asset updateAssetCondition(Long id, String condition, String notes) {
        return assetRepository.findById(id)
                .map(asset -> {
                    asset.setAssetCondition(condition);
                    return assetRepository.save(asset);
                })
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Asset> getAssetsByStatus(String status) {
        return assetRepository.findByAssetConditionWithAssignments(status);
    }
}