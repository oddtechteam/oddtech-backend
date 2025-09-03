package com.complaint.backend.services.Customer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.complaint.backend.dtos.LoginDTO;

import com.complaint.backend.entities.Customer;

import com.complaint.backend.repositories.CustomerRepository;

@Service
public class CustomerService {
    @Autowired
    private CustomerRepository customerRepository;

    


    public boolean addcustomer(Customer customer) {
         // Check if email or phone already exists
         /*if (customerRepository.findByEmail(customer.getEmail()) != null) {
            System.err.println("Duplicate email: " + customer.getEmail());
            return false; // Prevent adding a duplicate email
        }
        if (customerRepository.findByPhone(customer.getPhone()) != null) {
            System.err.println("Duplicate phone: " + customer.getPhone());
            return false; // Prevent adding a duplicate phone number
        }*/
        
        try {
            customerRepository.save(customer);
            System.out.println("signup successful");
            return true;
        } catch (Exception e) {
            e.printStackTrace();  // Log the exception for debugging
            System.err.println("Error adding customer: " + e.getMessage());
            return false;
        }
    }


    public Customer loginRequest(LoginDTO loginDTO) {
        Customer dbcustomer = customerRepository.findByEmail(loginDTO.getEmail());

        if (dbcustomer == null || dbcustomer.getPassword() == null) {
            return null; 
        }

        if (loginDTO.getPassword().equals(dbcustomer.getPassword())) {
            return dbcustomer; 
        }

        return null; // Invalid credentials
    }



    
}

