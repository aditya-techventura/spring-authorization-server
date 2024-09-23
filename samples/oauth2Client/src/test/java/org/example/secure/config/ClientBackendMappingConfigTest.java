package org.example.secure.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ClientBackendMappingConfigTest {

	@Autowired
	ClientBackendMappingConfigs clientBackendMappingConfigs;

	@BeforeEach
	void setUp() {
	}

	@AfterEach
	void tearDown() {
	}

	@Test
	void configProperties() {
		System.out.println(clientBackendMappingConfigs.clientBackendMapping);
	}

}