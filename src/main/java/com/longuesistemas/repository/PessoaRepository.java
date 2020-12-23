package com.longuesistemas.repository;

import org.socialsignin.spring.data.dynamodb.repository.EnableScan;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.longuesistemas.dto.Pessoa;

@EnableScan
@Repository
public interface PessoaRepository extends CrudRepository<Pessoa, String>{

}
