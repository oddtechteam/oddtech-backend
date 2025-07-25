package com.complaint.backend.entities;

import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Asset {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String productId;

    private String name;
    private String type;
    private String serialNumber;

    @Column(name = "asset_condition")
    private String assetCondition; // Status field

    @OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AssetAssignment> assignments = new ArrayList<>();

    @OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AssetRequest> assetRequests = new ArrayList<>();

    // Getters & Setters
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

    public List<AssetAssignment> getAssignments() { return assignments; }
    public void setAssignments(List<AssetAssignment> assignments) { this.assignments = assignments; }

    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }

    // Add these new methods for assetRequests
    public List<AssetRequest> getAssetRequests() {
        return assetRequests;
    }

    public void setAssetRequests(List<AssetRequest> assetRequests) {
        this.assetRequests = assetRequests;
    }
}