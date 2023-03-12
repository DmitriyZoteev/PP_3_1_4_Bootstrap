package ru.kata.spring.boot_security.demo.dao;

import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;
import java.util.Set;

public interface UserDao {
    void saveNewUser(User user);

    void editUser(User user);

    void deleteUser(Long id);

    List<User> getUsers();

    User getUserById(Long id);

    Set<Role> getRoles();

    User getUserByUserName(String username);
}
