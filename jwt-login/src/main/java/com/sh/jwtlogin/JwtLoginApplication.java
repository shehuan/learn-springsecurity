package com.sh.jwtlogin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Repository;

@SpringBootApplication
@MapperScan(basePackages = "com.sh.jwtlogin.dao", annotationClass = Repository.class)
public class JwtLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtLoginApplication.class, args);
	}

}
