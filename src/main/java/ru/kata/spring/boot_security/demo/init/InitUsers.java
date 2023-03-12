package ru.kata.spring.boot_security.demo.init;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;


@Component
public class InitUsers {

    private final UserService userService;

    private final RoleService roleService;

    private final PasswordEncoder bCryptPasswordEncoder;

    public InitUsers(UserService userService, RoleService roleService, PasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostConstruct
    public void init() {
        User user = new User("Nike3.68@mail.ru", "11112222"
                , "Dmitry", "Zoteev", (byte) 27);
        saveNewUser(user, "ROLE_USER");
        user = new User("SergeyAdmin@gmail.ru", "22223333"
                , "Sergey", "Ivanov", (byte) 30);
        saveNewUser(user, "ROLE_ADMIN", "ROLE_USER");
    }

    public void saveNewUser(User user, String... rolesNames) {
        try {
            userService.getUserByUserName(user.getUsername());
            return;
        } catch (EmptyResultDataAccessException e) {
            userService.saveNewUser(user);
        }
        Set<Role> roles = new HashSet<>();
        for (String roleName : rolesNames) {
            try {
                roleService.getRoleByName(roleName);
            } catch (EmptyResultDataAccessException e) {
                roleService.saveOrChangeRole(new Role(roleName));
            }
            roles.add(roleService.getRoleByName(roleName));
        }
        user = userService.getUserByUserName(user.getUsername());
        user.setRoles(roles);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userService.editUser(user);
    }
}
