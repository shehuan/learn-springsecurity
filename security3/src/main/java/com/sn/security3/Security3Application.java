package com.sn.security3;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Repository;

@SpringBootApplication
@MapperScan(basePackages = "com.sn.security3.dao", annotationClass = Repository.class)
public class Security3Application {

	public static void main(String[] args) {
		SpringApplication.run(Security3Application.class, args);
	}

}
