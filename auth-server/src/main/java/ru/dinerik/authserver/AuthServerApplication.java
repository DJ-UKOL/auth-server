package ru.dinerik.authserver;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.dinerik.authserver.users.User;
import ru.dinerik.authserver.users.UserRepository;

@SpringBootApplication
public class AuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();         // применяет надежное шифрование bcrypt
	}

	@Bean
	public ApplicationRunner dataLoader(
			UserRepository repo, PasswordEncoder encoder) {
		return args -> {
			repo.save(
					new User("habuma", encoder.encode("password"), "ROLE_ADMIN"));
			repo.save(
					new User("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
		};
	}

}
