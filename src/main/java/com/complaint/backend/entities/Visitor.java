package com.complaint.backend.entities;

import com.complaint.backend.enums.VisitorStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Table(name = "visitors")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Visitor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String vehicleDetails;
    private String assets;
    private String reason;

    @Column(name = "entry_time")
    private LocalDateTime expectedEntryTime;

    @Column(name = "exit_time")
    private LocalDateTime expectedExitTime;

    @Lob
    @Column(name = "photo_base64", columnDefinition = "LONGTEXT")
    private String photoBase64;

    @Enumerated(EnumType.STRING) // This stores the enum as a string in the database
    private VisitorStatus status;
}