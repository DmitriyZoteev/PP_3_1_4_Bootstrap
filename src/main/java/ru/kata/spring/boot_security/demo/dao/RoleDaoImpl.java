package ru.kata.spring.boot_security.demo.dao;

import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.demo.model.Role;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class RoleDaoImpl implements RoleDao {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void saveOrChangeRole(Role role) {
        if (role.getId() != null) {
            entityManager.merge(role);
        } else {
            entityManager.persist(role);
        }
    }

    @Override
    public void deleteRole(Long id) {
        entityManager.remove(getRoleById(id));
    }

    @Override
    public List<Role> getRoles() {
        return entityManager.createQuery("from Role").getResultList();
    }

    @Override
    public Role getRoleById(Long id) {
        return entityManager.find(Role.class, id);
    }

    @Override
    public Role getRoleByName(String name) {
        return (Role) entityManager.createQuery("from Role where name =: name").setParameter("name", name).getSingleResult();
    }
}
