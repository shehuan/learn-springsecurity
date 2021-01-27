package com.sn.security3.dao;


import com.sn.security3.bean.Menu;
import com.sn.security3.bean.Role;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MenuDao {
    List<Menu> findAllMenus();

    List<Role> findRolesByMenuId(Long menuId);
}
