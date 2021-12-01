package com.sh.security4.dao;


import com.sh.security4.bean.Menu;
import com.sh.security4.bean.Role;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MenuDao {
    List<Menu> findAllMenus();

    List<Role> findRolesByMenuId(Long menuId);
}
