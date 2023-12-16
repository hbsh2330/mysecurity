package com.example.demo.repository;

import com.example.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD 함수를 JpaRepository가 가지고 있음
// @Repository라는 어노테이션이 없어도 IOC(bean으로 등록)가 됨. 이유는 JpaRepository를 상속받았기 때문
public interface UserRepository extends JpaRepository<User, Integer> {

    User findByUsername(String username); //JPA Query method

}
