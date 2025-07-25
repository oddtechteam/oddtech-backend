package com.complaint.backend.dtos;

public class AssetIssueDTO {
    private Long assetId;
    private Long reportedById;
    private String issueType;
    private String description;
    private String stepsToReproduce;
    private String priority;

    // Getters and setters
    public Long getAssetId() { return assetId; }
    public void setAssetId(Long assetId) { this.assetId = assetId; }
    public Long getReportedById() { return reportedById; }
    public void setReportedById(Long reportedById) { this.reportedById = reportedById; }
    public String getIssueType() { return issueType; }
    public void setIssueType(String issueType) { this.issueType = issueType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getStepsToReproduce() { return stepsToReproduce; }
    public void setStepsToReproduce(String stepsToReproduce) { this.stepsToReproduce = stepsToReproduce; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
}