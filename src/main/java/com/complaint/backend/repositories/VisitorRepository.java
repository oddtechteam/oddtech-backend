// com.compaint.backend.repositories
package com.complaint.backend.repositories;

import com.complaint.backend.entities.Visitor;
import com.complaint.backend.enums.VisitorStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface VisitorRepository extends JpaRepository<Visitor, Long> {
    List<Visitor> findByStatus(VisitorStatus status);

    List<Visitor> findByNameContainingIgnoreCase(String name);
    List<Visitor> findByReasonContainingIgnoreCase(String reason);
}