package com.complaint.backend.services.socialmedia;

import com.complaint.backend.dtos.NoteDTO;
import com.complaint.backend.entities.Note;
import com.complaint.backend.entities.User;
import com.complaint.backend.repositories.NoteRepository;
import com.complaint.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class NoteServiceImpl implements NoteService{
	@Autowired
	 private final NoteRepository noteRepository;
	@Autowired
	    private final UserRepository userRepository;

	    public NoteServiceImpl(NoteRepository noteRepository, UserRepository userRepository) {
	        this.noteRepository = noteRepository;
	        this.userRepository = userRepository;
	    }

	    @Override
	    public List<NoteDTO> findAll() {
	        return noteRepository.findAll()
	                .stream()
	                .map(this::convertToDto)
	                .collect(Collectors.toList());
	    }

	    @Override
	    public List<NoteDTO> findByUser(User user) {
	        return noteRepository.findByUser(user)
	                .stream()
	                .map(this::convertToDto)
	                .collect(Collectors.toList());
	    }

	    @Override
	    public List<NoteDTO> findByUserId(Long userId) {
	        return noteRepository.findByUserId(userId)
	                .stream()
	                .map(this::convertToDto)
	                .collect(Collectors.toList());
	    }

	    @Override
	    public List<NoteDTO> findAllByOrderByCreatedAtDesc() {
	        return noteRepository.findAllByOrderByCreatedAtDesc()
	                .stream()
	                .map(this::convertToDto)
	                .collect(Collectors.toList());
	    }

	    @Override
	    public void deleteNote(Long noteId) {
	        noteRepository.deleteById(noteId);
	    }

//	    @Override
//	    public NoteDTO createNote(NoteDTO noteDto) {
//	        Optional<User> userOptional = userRepository.findById(noteDto.getUserId());
//	        if (userOptional.isEmpty()) {
//	            throw new RuntimeException("User not found with id: " + noteDto.getUserId());
//	        }
//
//	        Note note = new Note();
//	        note.setContent(noteDto.getContent());
//	        note.setCreatedAt(LocalDateTime.now());
//	        note.setUser(userOptional.get());
//
//	        Note savedNote = noteRepository.save(note);
//	        return convertToDto(savedNote);
//	    }
//
//		private NoteDTO convertToDto(Note savedNote) {
//			// TODO Auto-generated method stub
//			return null;  
//		}
	    

	    private NoteDTO convertToDto(Note savedNote) {
	        NoteDTO dto = new NoteDTO();
	        dto.setNoteId(savedNote.getNoteId());
	        dto.setContent(savedNote.getContent());
	        dto.setCreatedAt(savedNote.getCreatedAt());
	        dto.setUserId(savedNote.getUser().getId());
	        dto.setUserName(savedNote.getUser().getName()); 

	        return dto;
	    }
	    
	    @Override
	    public NoteDTO createNote(NoteDTO noteDto) {
	        // Get current authenticated user's email (from JWT 'sub' field)
	        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	        String email = authentication.getName();

	        // Find user by email
	        Optional<User> userOptional = userRepository.findFirstByEmail(email);
	        if (userOptional.isEmpty()) {
	            throw new RuntimeException("User not found with email: " + email);
	        }

	        // Create Note
	        Note note = new Note();
	        note.setContent(noteDto.getContent());
	        note.setCreatedAt(LocalDateTime.now());
	        note.setUser(userOptional.get());

	        // Save and return
	        Note savedNote = noteRepository.save(note);
	        return convertToDto(savedNote);
	    }


		
}
