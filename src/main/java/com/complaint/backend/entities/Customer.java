package com.complaint.backend.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Customer {
 
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long customerId;

    @NotNull
    @Size(min = 2, message = "First name should have at least 2 characters")
    private String firstName;

    @NotNull
    @Size(min = 2, message = "Last name should have at least 2 characters")
    private String lastName;

    @NotNull
    @Email(message = "Email should be valid")
    @Column(unique = true)
    private String email;

    @NotNull
    @Column(unique = true)
    private Long phone;

    @NotNull
    @Size(min = 5, message = "Address should have at least 5 characters")
    private String address;

    @NotNull
    @Size(min = 6, message = "Password should have at least 6 characters")
    private String password;

    




    
}








