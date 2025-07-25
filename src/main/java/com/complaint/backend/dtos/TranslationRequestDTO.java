package com.complaint.backend.dtos;

import lombok.Data;

@Data
public class TranslationRequestDTO {
    private String text;
    private String sourceLang = "en";
    private String targetLang;

    
    public void setText(String text) {
        this.text = text;
    }

    public void setSourceLang(String sourceLang) {
        this.sourceLang = sourceLang;
    }

    public void setTargetLang(String targetLang) {
        this.targetLang = targetLang;
    }


    public String getText() {
        return text;
    }

    public String getSourceLang() {
        return sourceLang;
    }

    public String getTargetLang() {
        return targetLang;
    }

}