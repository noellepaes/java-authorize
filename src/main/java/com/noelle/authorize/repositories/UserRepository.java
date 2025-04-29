package com.noelle.authorize.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.noelle.authorize.domain.user.User;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
}
