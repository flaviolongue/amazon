package com.longuesistemas.amazon.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.longuesistemas.amazon.config.ConstantConfiguration;
import com.longuesistemas.dto.Pessoa;
import com.longuesistemas.repository.PessoaRepository;

@RestController
@RequestMapping(ConstantConfiguration.PREFIX_API +  "/dynamo")
public class DynamoController {
	
	@Autowired
	private PessoaRepository pessoaRepository;
	
	
	@GetMapping("/aws/insert")
	public ResponseEntity<Pessoa> inserir() {
		Pessoa pessoa = new Pessoa();
		pessoa.setNome("Flavio aws");
		pessoaRepository.save(pessoa);
		return ResponseEntity.ok(pessoa);
	}
	
	@GetMapping("/aws/obter")
	public List<Pessoa> obterTodos() {
		List<Pessoa> pessoas = 	(List<Pessoa>) pessoaRepository.findAll();
		return pessoas;
	}
	
	@GetMapping("/aws/hello")
	public String obter() {
		
		return "Hello!!!";
	}

}
