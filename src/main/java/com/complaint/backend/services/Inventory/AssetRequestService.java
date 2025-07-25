package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetRequestDTO;
import com.complaint.backend.entities.AssetAssignment;
import com.complaint.backend.entities.AssetRequest;

import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface AssetRequestService {
    AssetRequest createRequest(AssetRequestDTO requestDTO);
    List<AssetRequest> getPendingRequests();

    @Transactional(readOnly = true)
    List<AssetRequest> getPendingRequestsWithDetails();

    AssetAssignment approveRequest(Long requestId);
    AssetRequest rejectRequest(Long requestId);


}