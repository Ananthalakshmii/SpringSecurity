package com.accolite.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
@RequestMapping("/")
public class TemplateController {
	
	@GetMapping("login")
	public String getLoginView() {
		return "login"; //same name as htm
	}
	
	@GetMapping("courses")
	public String getCourses() {
		return "courses";
	}

}
