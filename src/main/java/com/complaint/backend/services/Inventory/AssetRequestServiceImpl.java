package com.complaint.backend.services.Inventory;

import com.complaint.backend.dtos.AssetRequestDTO;
import com.complaint.backend.dtos.AssetAssignmentDTO;
import com.complaint.backend.entities.*;
import com.complaint.backend.exception.ResourceNotFoundException;
import com.complaint.backend.repositories.AssetRepository;
import com.complaint.backend.repositories.AssetRequestRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

@Service
public class AssetRequestServiceImpl implements AssetRequestService {

    @Autowired
    private AssetRequestRepository requestRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AssetAssignmentService assignmentService;

    @Override
    @Transactional
    public AssetRequest createRequest(AssetRequestDTO requestDTO) {
        User employee = userRepository.findById(requestDTO.getEmployeeId())
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        Asset asset = assetRepository.findById(requestDTO.getAssetId())
                .orElseThrow(() -> new ResourceNotFoundException("Asset not found"));

        AssetRequest request = new AssetRequest();
        request.setEmployee(employee);
        request.setAsset(asset);
        request.setRequestDate(new Date());
        request.setReason(requestDTO.getReason());
        request.setUrgency(requestDTO.getUrgency());
        request.setStatus("PENDING");

        return requestRepository.save(request);
    }

    @Override
    public List<AssetRequest> getPendingRequests() {
        return requestRepository.findByStatus("PENDING");
    }

    @Override
    @Transactional(readOnly = true)
    public List<AssetRequest> getPendingRequestsWithDetails() {
        List<AssetRequest> requests = requestRepository.findPendingRequestsWithDetails();
        // Ensure all requests have a reason
        requests.forEach(request -> {
            if (request.getReason() == null) {
                request.setReason("No reason provided");
            }
        });
        return requests;
    }

    @Override
    @Transactional
    public AssetAssignment approveRequest(Long requestId) {
        AssetRequest request = requestRepository.findById(requestId)
                .orElseThrow(() -> new ResourceNotFoundException("Request not found"));

        request.setStatus("APPROVED");
        requestRepository.save(request);

        AssetAssignmentDTO assignmentDTO = new AssetAssignmentDTO();
        assignmentDTO.setEmployeeId(request.getEmployee().getId());
        assignmentDTO.setAssetId(request.getAsset().getId());
        assignmentDTO.setAssignmentDate(new Date());
        assignmentDTO.setExpectedReturnDate(request.getExpectedReturnDate());
        assignmentDTO.setNotes(request.getReason());
        assignmentDTO.setStatus("ACTIVE");

        return assignmentService.createAssignment(assignmentDTO);
    }

    @Override
    @Transactional
    public AssetRequest rejectRequest(Long requestId) {
        AssetRequest request = requestRepository.findById(requestId)
                .orElseThrow(() -> new ResourceNotFoundException("Request not found"));

        request.setStatus("REJECTED");
        return requestRepository.save(request);
    }
}