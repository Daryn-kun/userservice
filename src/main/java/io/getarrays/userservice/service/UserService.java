package io.getarrays.userservice.service;

import io.getarrays.userservice.entity.AppUser;
import io.getarrays.userservice.entity.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
