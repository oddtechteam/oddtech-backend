// com.compaint.backend.dtos
package com.complaint.backend.dtos;

import com.complaint.backend.entities.Visitor;
import com.complaint.backend.enums.VisitorStatus;
import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class VisitorDto {
    private Long id;
    private String name;
    private String vehicleDetails;
    private String assets;
    private String reason;


    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime expectedEntryTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime expectedExitTime;

    private String photoBase64;

    @JsonEnumDefaultValue
    private VisitorStatus status;

    public Visitor toEntity() {
        Visitor visitor = new Visitor();
        visitor.setName(this.name);
        visitor.setVehicleDetails(this.vehicleDetails);
        visitor.setAssets(this.assets);
        visitor.setReason(this.reason);
        visitor.setExpectedEntryTime(this.expectedEntryTime);
        visitor.setExpectedExitTime(this.expectedExitTime);
        visitor.setPhotoBase64(this.photoBase64);
        // Note: status, actualEntryTime, actualExitTime are not set here as they're handled in service
        return visitor;
    }

    // In VisitorDto.java
    public static VisitorDto fromEntity(Visitor visitor) {
        VisitorDto dto = new VisitorDto();
        // Only include fields needed by frontend
        dto.setId(visitor.getId());
        dto.setName(visitor.getName());
        dto.setVehicleDetails(visitor.getVehicleDetails());
        dto.setReason(visitor.getReason());
        dto.setExpectedEntryTime(visitor.getExpectedEntryTime());
        dto.setPhotoBase64(visitor.getPhotoBase64());
        dto.setStatus(visitor.getStatus());

        return dto;
    }
}

