package com.kotkot.myDemo.security;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller

public class SecurityController {

    @GetMapping("/login")
    public String getLoginPage(Model model) {
        return "loginPage";
    }


    @GetMapping("/api/logout-page")
    public String getLogoutPage(Model model) {
        return "logoutPage";
    }

    @GetMapping("/api/home")
    @ResponseBody
    public String getHomePage(Model model) {
        return "Hello You Are in Home Page ";
    }

}
