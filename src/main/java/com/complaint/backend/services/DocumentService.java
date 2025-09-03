package com.complaint.backend.services;



import com.complaint.backend.entities.Document;
import com.complaint.backend.repositories.DocumentRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@Service
public class DocumentService {

 private final DocumentRepository documentRepository;
 
 @Value("{file.upload-dir}")
 private String uploadDir;

 public DocumentService(DocumentRepository documentRepository) {
     this.documentRepository = documentRepository;
 }

 public List<Document> getDocuments(Long userId, String type, String search) {
     if (type != null && type.equals("all")) {
         type = null;
     }
     return documentRepository.findByUserIdAndFilters(userId, type, search);
 }

 public Document uploadDocument(
     MultipartFile file,
     String name,
     String description,
     Long userId
 ) throws IOException {
     // Create upload directory if not exists
     Path uploadPath = Paths.get(uploadDir);
     if (!Files.exists(uploadPath)) {
         Files.createDirectories(uploadPath);
     }

     // Generate unique filename
     String originalFilename = file.getOriginalFilename();
     String fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
     String uniqueFileName = UUID.randomUUID() + fileExtension;
     Path filePath = uploadPath.resolve(uniqueFileName);
     
     // Save file
     Files.copy(file.getInputStream(), filePath);
     
     // Determine file type
     String type = getFileType(fileExtension.toLowerCase());
     
     // Create document entity
     Document document = new Document();
     document.setName(name);
     document.setType(type);
     document.setSize(file.getSize());
     document.setDescription(description);
     document.setFilePath(uniqueFileName);
     document.setUserId(userId);
     document.setUploadDate(LocalDate.now());
     
     return documentRepository.save(document);
 }

 private String getFileType(String extension) {
     if (extension.equals(".pdf")) return "pdf";
     if (extension.equals(".doc") || extension.equals(".docx")) return "doc";
     if (extension.equals(".xls") || extension.equals(".xlsx")) return "xls";
     if (extension.equals(".jpg") || extension.equals(".jpeg") || 
         extension.equals(".png") || extension.equals(".gif")) return "img";
     return "file";
 }

 public void deleteDocument(Long id) throws IOException {
     Document document = documentRepository.findById(id)
         .orElseThrow(() -> new RuntimeException("Document not found"));
     
     // Delete file from filesystem
     Path filePath = Paths.get(uploadDir + File.separator + document.getFilePath());
     Files.deleteIfExists(filePath);
     
     documentRepository.delete(document);
 }
}