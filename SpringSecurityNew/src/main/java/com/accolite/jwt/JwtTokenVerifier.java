package com.accolite.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtTokenVerifier extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authorizationHeader=request.getHeader("Authorization");
		
		if(Strings.isNullOrEmpty(authorizationHeader) || !(authorizationHeader.startsWith("Bearer "))) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String token=authorizationHeader.replace("Bearer ", "");
		
		try {
			
			String secretKey="secretkeyLongkeyForJwtNotEasilyDecodable";
			
			Jws<Claims> claimsJws = Jwts.parser()
				.setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
				.parseClaimsJws(token); // compact() ->will give signed Jwt ->called as JWS
			
			Claims body= claimsJws.getBody();
			
			String username=body.getSubject(); //name- linda //sub
			var authorities= (List<Map<String, String>>) body.get("authorities"); // from claim in the previous example- same name should be
			
			Set<SimpleGrantedAuthority> simpleGrantedAuthorities= authorities.stream()
					.map(m-> new SimpleGrantedAuthority(m.get("authority")))
					.collect(Collectors.toSet());
			
			Authentication authentication=new UsernamePasswordAuthenticationToken(username,null, simpleGrantedAuthorities);
			
			//authenticating the username with the given token
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			}catch (JwtException e) {
				throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
			}
		
		filterChain.doFilter(request, response);
		
	}

}
