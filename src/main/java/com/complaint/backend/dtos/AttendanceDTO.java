package com.complaint.backend.dtos;

import java.time.LocalDateTime;

public class AttendanceDTO {

    private String name;
    private String email;
    private LocalDateTime time;
    private double lat;
    private double lng;
    private String photo;
    private String status;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    // ✅ Constructor
    public AttendanceDTO(String name, String email, LocalDateTime time, double lat, double lng, String photo, String status) {
        this.name = name;
        this.email = email;
        this.time = time;
        this.lat = lat;
        this.lng = lng;
        this.photo = photo;
        this.status = status;

    }

    // ✅ Getters
    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public LocalDateTime getTime() {
        return time;
    }

    public double getLat() {
        return lat;
    }

    public double getLng() {
        return lng;
    }

    public String getPhoto() {
        return photo;
    }

    // ✅ Setters
    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setTime(LocalDateTime time) {
        this.time = time;
    }

    public void setLat(double lat) {
        this.lat = lat;
    }

    public void setLng(double lng) {
        this.lng = lng;
    }

    public void setPhoto(String photo) {
        this.photo = photo;
    }
}
