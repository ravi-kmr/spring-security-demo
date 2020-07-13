package com.app.ravi.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.app.ravi.model.UserDto;

public interface UsersService extends UserDetailsService {

	UserDto createUser(UserDto userDetails);
	UserDto getUserDetailsByEmail(String email);
	UserDto getUserByUserId(String userId);
}
