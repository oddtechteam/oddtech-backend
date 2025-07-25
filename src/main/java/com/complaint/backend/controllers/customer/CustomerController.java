package com.complaint.backend.controllers.customer;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complaint.backend.dtos.LoginDTO;
import com.complaint.backend.entities.Customer;
import com.complaint.backend.services.Customer.CustomerService;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/customer")

public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @PostMapping("/insert")
public ResponseEntity<Map<String, String>> addcustomer(@Valid @RequestBody Customer customer) {
    Map<String, String> response = new HashMap<>();
    boolean isAdded = customerService.addcustomer(customer);

    if (isAdded) {
        response.put("message", "Customer added successfully");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    } else {
        response.put("message", "Failed to add customer");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
   



    @PostMapping("/loginCustomer")
    public ResponseEntity<?> userCredentials(@RequestBody LoginDTO loginDTO, HttpSession session) {
        Customer customer = customerService.loginRequest(loginDTO);

        if (customer != null) {
            session.setAttribute("customer", customer);
            return ResponseEntity.ok(customer);
        } else {
            session.setAttribute("customer", null);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
}


