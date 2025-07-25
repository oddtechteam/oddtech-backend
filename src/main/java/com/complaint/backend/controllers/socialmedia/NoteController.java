package com.complaint.backend.controllers.socialmedia;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.dtos.NoteDTO;
import com.complaint.backend.services.socialmedia.NoteService;

@RestController
@RequestMapping("/api/note")
@CrossOrigin(origins = "http://localhost:5173")
public class NoteController {
    @Autowired
    private final NoteService noteService;


    public NoteController(NoteService noteService) {
        this.noteService = noteService;
    }

    //  Create a new note

    @PostMapping("/createnote")
    public ResponseEntity<NoteDTO> createNote(@RequestBody NoteDTO noteDTO) {
        NoteDTO createdNote = noteService.createNote(noteDTO);
        return ResponseEntity.ok(createdNote);
    }


    //  Get all notes

    @GetMapping("/allnotes")
    public ResponseEntity<List<NoteDTO>> getAllNotes() {
        return ResponseEntity.ok(noteService.findAllByOrderByCreatedAtDesc());
    }

    // Get notes by user ID

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<NoteDTO>> getNotesByUserId(@PathVariable Long userId) {
        return ResponseEntity.ok(noteService.findByUserId(userId));
    }

    //  Delete note by ID

    @DeleteMapping("/{noteId}")
    public ResponseEntity<String> deleteNote(@PathVariable Long noteId) {
        noteService.deleteNote(noteId);
        return ResponseEntity.ok("Note deleted successfully");
    }
}