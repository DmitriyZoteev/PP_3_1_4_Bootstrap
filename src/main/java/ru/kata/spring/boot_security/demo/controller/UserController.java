package ru.kata.spring.boot_security.demo.controller;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.security.Principal;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


@Controller
public class UserController {

    private final UserService userService;

    private final RoleService roleService;

    private final PasswordEncoder bCryptPasswordEncoder;

    public UserController(UserService userService, RoleService roleService, PasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @GetMapping(value = "/admin")
    public String getUsers(Model model, Principal principal) {
        model.addAttribute("usersList", userService.getUsers());
        User currentUser = userService.getUserByUserName(principal.getName());
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("user", new User());
        model.addAttribute("rolesList", userService.getRoles());
        return "adminPage";
    }


    @PostMapping("/admin/saveNewUser")
    public String saveNewUser(@RequestParam(name = "roles", required = false) String checkedRoles, HttpServletRequest request,
                              @Valid @ModelAttribute("user") User user, BindingResult bindingResult) {
        Set<Role> roles = new HashSet<>();
        if (checkedRoles != null) {
            Set<Role> rolesFromBD = userService.getRoles();
            for (Role role : rolesFromBD) {
                if (checkedRoles.contains(role.getName())) {
                    roles.add(role);
                }
            }
        } else {
            roles.add(roleService.getRoleByName("ROLE_USER"));
        }
        user.setRoles(roles);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        try {
            userService.saveNewUser(user);
        } catch (DataIntegrityViolationException e) {
            if (Objects.requireNonNull(e.getRootCause()).toString().contains('\'' + user.getUsername() + '\'')) {
                bindingResult.addError(new ObjectError("user", user.getUsername() + " уже существует"));
            }
        }
        return "redirect:/admin";
    }

    @PostMapping("/admin/editUser")
    public String editUser(@RequestParam(name = "roles", required = false) String checkedRoles, @Valid @ModelAttribute("user") User user
            , BindingResult bindingResult) {
        User userFromBD = userService.getUserById(user.getId());
        userFromBD.setUsername(user.getUsername());
        userFromBD.setFirst_name(user.getFirst_name());
        userFromBD.setLast_name(user.getLast_name());
        userFromBD.setAge(user.getAge());
        Set<Role> roles = new HashSet<>();
        if (checkedRoles != null) {
            Set<Role> rolesFromBD = userService.getRoles();
            for (Role role : rolesFromBD) {
                if (checkedRoles.contains(role.getName())) {
                    roles.add(role);
                }
            }
            userFromBD.setRoles(roles);
        }
        if (!user.getNewPassword().isBlank()) {
            userFromBD.setPassword(bCryptPasswordEncoder.encode(user.getNewPassword()));
        }
        try {
            userService.editUser(userFromBD);
        } catch (DataIntegrityViolationException e) {
            if (Objects.requireNonNull(e.getRootCause()).toString().contains('\'' + user.getUsername() + '\'')) {
                bindingResult.addError(new ObjectError("user", user.getUsername() + " уже существует"));
            }
        }
        return "redirect:/admin";
    }

    @RequestMapping("/admin/deleteUser/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

    @GetMapping(value = "/user")
    public String pageForUser(Model model, Principal principal) {
        User currentUser = userService.getUserByUserName(principal.getName());
        model.addAttribute("currentUser", currentUser);
        return "userPage";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            request.getSession().invalidate();
        }
        return "redirect:/login";
    }
}
