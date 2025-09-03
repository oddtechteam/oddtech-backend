// VisitorServiceImpl.java
package com.complaint.backend.services.EntryGate;

import com.complaint.backend.dtos.VisitorDto;
import com.complaint.backend.entities.User;
import com.complaint.backend.entities.Visitor;
import com.complaint.backend.enums.VisitorStatus;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.VisitorRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class VisitorServiceImpl implements VisitorService {

    private final VisitorRepository visitorRepository;

    @Autowired
    public VisitorServiceImpl(VisitorRepository visitorRepository) {
        this.visitorRepository = visitorRepository;
    }



    @Override
    public VisitorDto createVisitor(VisitorDto visitorDto) {

        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();


        // Validate required fields
        if (visitorDto.getName() == null || visitorDto.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Visitor name is required");
        }
        if (visitorDto.getReason() == null || visitorDto.getReason().trim().isEmpty()) {
            throw new IllegalArgumentException("Visit reason is required");
        }
        if (visitorDto.getExpectedEntryTime() == null) {
            throw new IllegalArgumentException("Expected entry time is required");
        }

        try {
            Visitor visitor = visitorDto.toEntity();
            visitor.setStatus(VisitorStatus.PENDING);

            // Handle photo if present
            if (visitorDto.getPhotoBase64() != null) {
                // If it has the data:image prefix, extract just the Base64 part
                if (visitorDto.getPhotoBase64().startsWith("data:image")) {
                    String[] parts = visitorDto.getPhotoBase64().split(",");
                    if (parts.length > 1) {
                        visitor.setPhotoBase64(parts[1]);
                    }
                } else {
                    visitor.setPhotoBase64(visitorDto.getPhotoBase64());
                }
            }

            Visitor savedVisitor = visitorRepository.save(visitor);
            return VisitorDto.fromEntity(savedVisitor);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create visitor: " + e.getMessage(), e);
        }
    }


    @Override
    public VisitorDto updateVisitor(Long id, VisitorDto visitorDto) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));

        visitor.setName(visitorDto.getName());
        visitor.setVehicleDetails(visitorDto.getVehicleDetails());
        visitor.setAssets(visitorDto.getAssets());
        visitor.setReason(visitorDto.getReason());
        visitor.setExpectedEntryTime(visitorDto.getExpectedEntryTime());
        visitor.setExpectedExitTime(visitorDto.getExpectedExitTime());
        visitor.setPhotoBase64(visitorDto.getPhotoBase64());

        Visitor updatedVisitor = visitorRepository.save(visitor);
        return VisitorDto.fromEntity(updatedVisitor);
    }

    @Override
    public VisitorDto getVisitorById(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));
        return VisitorDto.fromEntity(visitor);
    }

    @Override
    public List<VisitorDto> getAllVisitors() {
        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return visitorRepository.findAll().stream()
                .map(VisitorDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public List<VisitorDto> getVisitorsByStatus(String status) {
        VisitorStatus visitorStatus = VisitorStatus.valueOf(status.toUpperCase());
        return visitorRepository.findByStatus(visitorStatus).stream()
                .map(VisitorDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public List<VisitorDto> searchVisitors(String query) {
        List<Visitor> visitorsByName = visitorRepository.findByNameContainingIgnoreCase(query);
        List<Visitor> visitorsByReason = visitorRepository.findByReasonContainingIgnoreCase(query);

        visitorsByName.addAll(visitorsByReason.stream()
                .filter(v -> !visitorsByName.contains(v))
                .collect(Collectors.toList()));

        return visitorsByName.stream()
                .map(VisitorDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public VisitorDto approveVisitor(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));

        visitor.setStatus(VisitorStatus.APPROVED);

        Visitor updatedVisitor = visitorRepository.save(visitor);
        return VisitorDto.fromEntity(updatedVisitor);
    }

    @Override
    public VisitorDto rejectVisitor(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));

        visitor.setStatus(VisitorStatus.REJECTED);
        Visitor updatedVisitor = visitorRepository.save(visitor);
        return VisitorDto.fromEntity(updatedVisitor);
    }

    @Override
    public VisitorDto setEntryTime(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));

        Visitor updatedVisitor = visitorRepository.save(visitor);
        return VisitorDto.fromEntity(updatedVisitor);
    }

    @Override
    public VisitorDto setExitTime(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));

        visitor.setStatus(VisitorStatus.COMPLETED);
        Visitor updatedVisitor = visitorRepository.save(visitor);
        return VisitorDto.fromEntity(updatedVisitor);
    }

    @Override
    public void deleteVisitor(Long id) {
        Visitor visitor = visitorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Visitor not found with id: " + id));
        visitorRepository.delete(visitor);
    }
}