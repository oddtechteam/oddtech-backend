package com.complaint.backend.entities;

import jakarta.persistence.*;

import java.util.Date;

@Entity
public class AssetIssue {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne
    @JoinColumn(name = "reported_by_id")
    private User reportedBy;

    private String issueType;
    private String description;
    private String stepsToReproduce;
    private String priority; // LOW, MEDIUM, HIGH
    private String status; // OPEN, IN_PROGRESS, RESOLVED, CLOSED
    private String resolution;

    @Temporal(TemporalType.TIMESTAMP)
    private Date reportedDate;

    @Temporal(TemporalType.TIMESTAMP)
    private Date resolvedDate;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }
    public User getReportedBy() { return reportedBy; }
    public void setReportedBy(User reportedBy) { this.reportedBy = reportedBy; }
    public String getIssueType() { return issueType; }
    public void setIssueType(String issueType) { this.issueType = issueType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getStepsToReproduce() { return stepsToReproduce; }
    public void setStepsToReproduce(String stepsToReproduce) { this.stepsToReproduce = stepsToReproduce; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getResolution() { return resolution; }
    public void setResolution(String resolution) { this.resolution = resolution; }
    public Date getReportedDate() { return reportedDate; }
    public void setReportedDate(Date reportedDate) { this.reportedDate = reportedDate; }
    public Date getResolvedDate() { return resolvedDate; }
    public void setResolvedDate(Date resolvedDate) { this.resolvedDate = resolvedDate; }
}