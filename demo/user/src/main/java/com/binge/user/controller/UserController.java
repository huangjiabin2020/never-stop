package com.binge.user.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: never-stop
 * @description: 用户C层
 * @author: Mr.Huang
 * @create: 2022-06-18 14:58
 **/
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping
    public String hello() {
        return "world";
    }
}
