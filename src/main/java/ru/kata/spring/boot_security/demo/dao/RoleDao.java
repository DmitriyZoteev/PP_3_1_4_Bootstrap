package ru.kata.spring.boot_security.demo.dao;

import ru.kata.spring.boot_security.demo.model.Role;

import java.util.List;

public interface RoleDao {
    void saveOrChangeRole(Role role);

    void deleteRole(Long id);

    List<Role> getRoles();

    Role getRoleById(Long id);

    Role getRoleByName(String name);
}
