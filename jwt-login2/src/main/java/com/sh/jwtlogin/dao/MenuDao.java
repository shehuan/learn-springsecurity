package com.sh.jwtlogin.dao;


import com.sh.jwtlogin.bean.Menu;
import com.sh.jwtlogin.bean.Role;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MenuDao {
    List<Menu> findAllMenus();

    List<Role> findRolesByMenuId(Long menuId);
}
