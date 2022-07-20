package com.accolite.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.accolite.security.ApplicationUserRole;
import com.google.common.collect.Lists;

@Repository("fake") //tell spring that this class has to be instantiated and fake represents if there are many classes implementing and use this name
public class FakeApplicationUserDaoService implements ApplicationUserDao{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}

	private List<ApplicationUser> getApplicationUsers(){
		List<ApplicationUser> applicationUsers=Lists.newArrayList(
				new ApplicationUser("annasmith", 
						passwordEncoder.encode("password"), 
						ApplicationUserRole.STUDENT.getGrantedAuthorities(), 
						true, true, true, true),
				
				new ApplicationUser("linda", 
						passwordEncoder.encode("password123"), 
						ApplicationUserRole.ADMIN.getGrantedAuthorities(), 
						true, true, true, true),
				
				new ApplicationUser("tom", 
						passwordEncoder.encode("password123"), 
						ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), 
						true, true, true, true)
				
				);
		
		return applicationUsers;
	}
	
}
