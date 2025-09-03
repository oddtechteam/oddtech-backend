package com.complaint.backend.services.Inventory;

import com.complaint.backend.entities.Asset;
import java.util.List;

public interface AssetService {
    List<Asset> getAllAssets();
    Asset getAssetById(Long id);
    Asset saveAsset(Asset asset);
    Asset updateAsset(Long id, Asset asset);
    void deleteAsset(Long id);
    List<Asset> getAvailableAssets();
    Asset updateAssetCondition(Long id, String condition, String notes);
    List<Asset> getAssetsByStatus(String status);
}