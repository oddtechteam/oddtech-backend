package com.complaint.backend.controllers;



import com.complaint.backend.entities.Document;
import com.complaint.backend.services.DocumentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

 private final DocumentService documentService;

 public DocumentController(DocumentService documentService) {
     this.documentService = documentService;
 }

 @GetMapping
 public ResponseEntity<List<Document>> getDocuments(
     @RequestParam Long userId,
     @RequestParam(required = false) String type,
     @RequestParam(required = false) String search
 ) {
     return ResponseEntity.ok(documentService.getDocuments(userId, type, search));
 }

 @PostMapping(consumes = "multipart/form-data")
 public ResponseEntity<Document> uploadDocument(
     @RequestParam("file") MultipartFile file,
     @RequestParam String name,
     @RequestParam(required = false) String description,
     @RequestParam Long userId
 ) throws IOException {
     return ResponseEntity.ok(
         documentService.uploadDocument(file, name, description, userId)
     );
 }

 @DeleteMapping("/{id}")
 public ResponseEntity<Void> deleteDocument(@PathVariable Long id) throws IOException {
     documentService.deleteDocument(id);
     return ResponseEntity.noContent().build();
 }
}