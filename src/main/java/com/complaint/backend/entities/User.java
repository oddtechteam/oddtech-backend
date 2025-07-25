package com.complaint.backend.entities;

import java.util.Collection;
import java.util.List;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.complaint.backend.dtos.UserDTO;
import com.complaint.backend.enums.UserRole;

import lombok.Data;


@Entity
@Data
public class User implements UserDetails {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
    private String name;
    private String email;
    private String password;
    private UserRole userRole;
    private String faceImageName;

    public String getFaceEmbedding() {
        return faceEmbedding;
    }

    public String getFaceImageName() {
        return faceImageName;
    }

    public UserRole getUserRole() {
        return userRole;
    }


    @Override
    public String getPassword() {
        return password;
    }

    @Column(columnDefinition = "LONGTEXT")
    private String faceEmbedding;

    @Column(nullable = true)
    private String department;

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        this.department = department;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUserRole(UserRole userRole) {
        this.userRole = userRole;
    }

    public void setFaceImageName(String faceImageName) {
        this.faceImageName = faceImageName;
    }

    public void setFaceEmbedding(String faceEmbedding) {
        this.faceEmbedding = faceEmbedding;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserDTO getUserDTO() {
        UserDTO userDTO = new UserDTO();
        userDTO.setId(id);
        userDTO.setName(name);
        userDTO.setEmail(email);
        userDTO.setUserRole(userRole);

        return userDTO;
    }
    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
return List.of(new SimpleGrantedAuthority(userRole.name()));
}

@Override
public String getUsername() {
return email;
}

@Override
public boolean isAccountNonExpired() {
return true;
}


@Override
public boolean isAccountNonLocked() {
return true;
}

@Override
public boolean isCredentialsNonExpired() {
return true;
}

@Override
public boolean isEnabled() {
return true;
}



}