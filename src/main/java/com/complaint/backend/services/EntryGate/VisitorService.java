// VisitorService.java
package com.complaint.backend.services.EntryGate;

import com.complaint.backend.dtos.VisitorDto;
import java.util.List;

public interface VisitorService {
    VisitorDto createVisitor(VisitorDto visitorDto);
    VisitorDto updateVisitor(Long id, VisitorDto visitorDto);
    VisitorDto getVisitorById(Long id);
    List<VisitorDto> getAllVisitors();
    List<VisitorDto> getVisitorsByStatus(String status);
    List<VisitorDto> searchVisitors(String query);
    VisitorDto approveVisitor(Long id);
    VisitorDto rejectVisitor(Long id);
    VisitorDto setEntryTime(Long id);
    VisitorDto setExitTime(Long id);
    void deleteVisitor(Long id);
}