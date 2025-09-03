package com.complaint.backend.dtos;

import lombok.Data;

@Data
public class TranslationResponseDTO {
    private String translatedText;
    public TranslationResponseDTO(String translatedText) {
        this.translatedText = translatedText;
    }

}