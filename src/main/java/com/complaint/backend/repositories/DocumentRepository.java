package com.complaint.backend.repositories;



import com.complaint.backend.entities.Document;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
 
	@Query("SELECT d FROM Document d WHERE d.userId = :userId AND " +
		       "(:type IS NULL OR d.type = :type) AND " +
		       "(LOWER(d.name) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
		       "LOWER(d.description) LIKE LOWER(CONCAT('%', :search, '%')))")

 List<Document> findByUserIdAndFilters(
     @Param("userId") Long userId,
     @Param("type") String type,
     @Param("search") String search
 );
 
 List<Document> findByUserId(Long userId);
}