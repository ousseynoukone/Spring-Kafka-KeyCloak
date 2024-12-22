package com.springdemo.springkafkakeycloak.Controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api")
public class HomeController {

//    @PreAuthorize("hasRole('User')")

    @GetMapping("/home")
   private String getHome(){
        return "Hello";
    }
}
