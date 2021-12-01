package com.sh.security4;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Repository;

@SpringBootApplication
@MapperScan(basePackages = "com.sh.security4.dao", annotationClass = Repository.class)
public class Security4Application {

	public static void main(String[] args) {
		SpringApplication.run(Security4Application.class, args);
	}

}
