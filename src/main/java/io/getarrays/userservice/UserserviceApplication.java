package io.getarrays.userservice;

import io.getarrays.userservice.entity.AppUser;
import io.getarrays.userservice.entity.Role;
import io.getarrays.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner run(UserService userService){
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new AppUser(null, "Daryn Nurlan", "daryn", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Assel Nurlan", "assel", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Daur Baimbet", "daur", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Alua Zhumakoja", "aruna", "1234", new ArrayList<>()));

            userService.addRoleToUser("aruna", "ROLE_USER");
            userService.addRoleToUser("assel", "ROLE_MANAGER");
            userService.addRoleToUser("daur", "ROLE_ADMIN");
            userService.addRoleToUser("daryn", "ROLE_SUPER_ADMIN");
        };
    }
}
