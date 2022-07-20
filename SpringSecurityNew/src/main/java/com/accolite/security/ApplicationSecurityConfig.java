package com.accolite.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.accolite.jwt.JwtTokenVerifier;
import com.accolite.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@SuppressWarnings(value = "deprecation")
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			/*
			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and()
			*/
			
			.csrf().disable()
			
			/* JWT configuration*/
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
			.addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)
			
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())//role based auth
			/*
			.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(),ApplicationUserRole.ADMINTRAINEE.name())//ant matchers go by order
			*/
			.anyRequest()
			.authenticated();
			
	/*		.and() //customize login page
			//.httpBasic();
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses",true) //to create customized login page
				.usernameParameter("username")
				.passwordParameter("password")
				
			.and() //customize remember Me
			.rememberMe()
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))//default to 2 weeks->change to 21 days
				.key("somethingverysecured")
				.rememberMeParameter("RememberMe")
			.and() //customize logout
			.logout()
		    //.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) 
				//if csrf enabled-it should be post, but since it is disabled- it can be anything.-- this happens behind
				.logoutUrl("/logout")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID","RememberMe")
				.logoutSuccessUrl("/login");
				
				
				*/
		}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}
	
	/*@Override
	@Bean
	protected UserDetailsService userDetailsService() { //retrieve user from DB
		UserDetails annaSmithUser = User.builder()
										.username("annasmith")
										.password(passwordEncoder.encode("password"))
										//.roles(ApplicationUserRole.STUDENT.name())//ROLE_STUDENT
										.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())//permission based auth
										.build();
		
		UserDetails lindaUser=User.builder()
								.username("linda")
								.password(passwordEncoder.encode("password123"))
								//.roles(ApplicationUserRole.ADMIN.name())//ROLE_ADMIN
								.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
								.build();
		
		UserDetails tomUser=User.builder()
				.username("tom")
				.password(passwordEncoder.encode("password123"))
				//.roles(ApplicationUserRole.ADMINTRAINEE.name())//ROLE_ADMINTRAINEE
				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
				.build();
		
		
		return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
	}
	*/
}
