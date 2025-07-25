package com.complaint.backend.controllers.Inventory;

import com.complaint.backend.dtos.AssetAssignmentDTO;
import com.complaint.backend.dtos.AssetDTO;
import com.complaint.backend.entities.Asset;
import com.complaint.backend.entities.AssetAssignment;
import com.complaint.backend.services.Inventory.AssetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/assets")
@CrossOrigin(origins = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
public class AssetController {

    @Autowired
    private AssetService assetService;

    @GetMapping
    public ResponseEntity<List<AssetDTO>> getAllAssets() {
        List<Asset> assets = assetService.getAllAssets();
        List<AssetDTO> assetDTOs = assets.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(assetDTOs);
    }

    @GetMapping("/available")
    public ResponseEntity<List<AssetDTO>> getAvailableAssets() {
        List<Asset> assets = assetService.getAvailableAssets();
        List<AssetDTO> assetDTOs = assets.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(assetDTOs);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssetDTO> getAssetById(@PathVariable Long id) {
        Asset asset = assetService.getAssetById(id);
        return asset != null ? ResponseEntity.ok(convertToDTO(asset)) : ResponseEntity.notFound().build();
    }

    @PostMapping
    public ResponseEntity<AssetDTO> createAsset(@RequestBody Asset asset) {
        Asset created = assetService.saveAsset(asset);
        return ResponseEntity.ok(convertToDTO(created));
    }

    @PutMapping("/{id}")
    public ResponseEntity<AssetDTO> updateAsset(@PathVariable Long id, @RequestBody Asset asset) {
        Asset updated = assetService.updateAsset(id, asset);
        return updated != null ? ResponseEntity.ok(convertToDTO(updated)) : ResponseEntity.notFound().build();
    }

    @PutMapping("/{id}/condition")
    public ResponseEntity<AssetDTO> updateAssetCondition(
            @PathVariable Long id,
            @RequestParam String condition,
            @RequestBody(required = false) Map<String, String> body) {

        String notes = body != null ? body.get("notes") : null;
        Asset updated = assetService.updateAssetCondition(id, condition, notes);
        return updated != null ? ResponseEntity.ok(convertToDTO(updated)) : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteAsset(@PathVariable Long id) {
        try {
            assetService.deleteAsset(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("message", "Error deleting asset: " + e.getMessage()));
        }
    }

    private AssetAssignmentDTO convertAssignmentToDTO(AssetAssignment assignment) {
        if (assignment == null) {
            return null;
        }

        AssetAssignmentDTO dto = new AssetAssignmentDTO();
        dto.setId(assignment.getId());

        if (assignment.getEmployee() != null) {
            dto.setEmployeeId(assignment.getEmployee().getId());
        }

        if (assignment.getAsset() != null) {
            dto.setAssetId(assignment.getAsset().getId());
        }

        dto.setAssignmentDate(assignment.getAssignmentDate());
        dto.setExpectedReturnDate(assignment.getExpectedReturnDate());
        dto.setActualReturnDate(assignment.getActualReturnDate());
        dto.setNotes(assignment.getNotes());
        dto.setStatus(assignment.getStatus());

        return dto;
    }

    private AssetDTO convertToDTO(Asset asset) {
        AssetDTO dto = new AssetDTO();
        dto.setId(asset.getId());
        dto.setProductId(asset.getProductId());
        dto.setName(asset.getName());
        dto.setType(asset.getType());
        dto.setSerialNumber(asset.getSerialNumber());
        dto.setAssetCondition(asset.getAssetCondition());


        if (asset.getAssignments() != null && !asset.getAssignments().isEmpty()) {
            List<AssetAssignmentDTO> assignmentDTOs = asset.getAssignments().stream()
                    .map(this::convertAssignmentToDTO)
                    .collect(Collectors.toList());
            dto.setAssignments(assignmentDTOs);
        }

        return dto;
    }
}