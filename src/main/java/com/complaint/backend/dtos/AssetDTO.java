package com.complaint.backend.dtos;

import java.util.List;

public class AssetDTO {
    private Long id;
    private String productId;
    private String name;
    private String type;
    private String serialNumber;
    private String assetCondition;
    private List<AssetAssignmentDTO> assignments;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getAssetCondition() { return assetCondition; }
    public void setAssetCondition(String assetCondition) { this.assetCondition = assetCondition; }

    public List<AssetAssignmentDTO> getAssignments() { return assignments; }
    public void setAssignments(List<AssetAssignmentDTO> assignments) { this.assignments = assignments; }

    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }
}