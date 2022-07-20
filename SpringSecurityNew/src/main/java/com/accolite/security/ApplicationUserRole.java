package com.accolite.security;

import java.util.Set;import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;
import static com.accolite.security.ApplicationUserPermission.*;

//import guava for using Sets using dependency
public enum ApplicationUserRole {
	
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,ApplicationUserPermission.COURSE_WRITE,ApplicationUserPermission.STUDENT_READ,ApplicationUserPermission.STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,ApplicationUserPermission.STUDENT_READ));
	
	private final Set<ApplicationUserPermission> permission;

	public Set<ApplicationUserPermission> getPermission() {
		return permission;
	}

	private ApplicationUserRole(Set<ApplicationUserPermission> permission) {
		this.permission = permission;
	}
	
	//to remove this line -- .roles(ApplicationUserRole.ADMINTRAINEE.name()) -- implementing following method
	public Set<SimpleGrantedAuthority> getGrantedAuthorities(){ //if we remove role() from applicationsecurityconfig, we have to implement this-- implement to create a role
		Set<SimpleGrantedAuthority> permissions = getPermission().stream()
		.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
		.collect(Collectors.toSet());
		permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
		return permissions;
	}
	

}
