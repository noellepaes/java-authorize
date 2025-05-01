package com.noelle.authorize.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

public class UserController {
        @GetMapping
    public ResponseEntity<String> getUser(){
        return ResponseEntity.ok("sucesso!");
    }
}
