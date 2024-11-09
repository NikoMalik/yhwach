package config

import "time"

func DefaultConfig() *Config {

	return &Config{
		AppAuthName: "TestAuthApp",
		Account: &Account{
			Password: &Password{
				MinLength:      8,
				MaxLength:      16,
				Power:          "medium",
				Special:        "!@#$%^&*",
				AcquireLogin:   true,
				AcquireRegistr: true,
				Recovery:       true,
				Enabled:        true,
			},
			UserName: &UserName{
				MinLength:             2,
				MaxLength:             16,
				Enabled:               true,
				AcquireOnLogin:        true,
				AcquireOnRegistration: true,
				UseAsLoginIdentifier:  true,
			},
			AllowDeletion: false,
			AllowSignup:   true,
			BanIp:         false,
			BanEmail:      false,
		},
		Email: &Email{
			SMTP_SERV: &SMTP{
				Host:     "smtp.example.com",
				User:     "user@example.com",
				Password: "password",
				Port:     587,
			},
			FromAddress:          "noreply@example.com",
			FromName:             "Test App",
			Limit:                5,
			Length:               64,
			MaxNumberofEmail:     100,
			RecquireVerification: true,
			EmailAsLogin:         true,
			AcquireEmail:         true,
			AcquireRegistr:       true,
			AcquireLogin:         true,
			Enable_Delivery:      true,
		},
		Database: &Database{
			Dialect:  "postgres",
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "password",
			Name:     "testdb",
			SSLMode:  "disable",
			Url:      "",
		},
		Keys: &Keys{
			Token:     "token_secret",
			UserVerif: "user_verification_secret",
			Limit:     5,
			Enabled:   true,
		},
		MFA: &MFA{
			OTP: &OTP{
				Secret:  "otp_secret",
				Skew:    1,
				Digits:  6,
				Period:  30,
				Enabled: true,
			},
			Keys: &Keys{
				Token:     "mfa_token_secret",
				UserVerif: "mfa_verification_secret",
				Limit:     10,
				Enabled:   true,
			},
			TOTP: &TOTP{
				Skew:    1,
				Enabled: true,
			},
			ThirdParty: &ThirdParty{
				Providers: &Providers{
					Github: &Provider{
						Name:     "Github",
						ClientID: "github_client_id",
						Secret:   "github_secret",
						Enabled:  true,
					},
					Google: &Provider{
						Name:     "Google",
						ClientID: "google_client_id",
						Secret:   "google_secret",
						Enabled:  true,
					},
				},
				AllowedRedirectUrls: []string{"https://example.com/redirect"},
				RedirectUrl:         "https://example.com/auth",
				DefaultRedirectUrl:  "https://example.com/default",
				Enabled:             true,
			},
			AcquireLogin:   true,
			AcquireRegistr: true,
		},
		SMTP: &SMTP{
			Host:     "localhost",
			User:     "user@example.com",
			Password: "password",
			Port:     587,
		},
		SecretKeys: &SecretKeys{
			Keys: []string{"ajfkahfakfhjahfj"},
		},
		RateLimiter: &RateLimiter{
			Enabled: true,
			PasscodeLimit: &RateLimit{
				Interval: time.Minute,
				Tokens:   5,
			},
			OtpLimit: &RateLimit{
				Interval: time.Minute,
				Tokens:   3,
			},
			TokenLimits: &RateLimit{
				Interval: time.Minute,
				Tokens:   3,
			},
			Cache_Type: MEMORY_CACHE_TYPE,
		},
		Session: &Session{
			// Define Session fields as needed
		},

		Server: &Server{

			GRPC: &GRPC{
				Host:        "localhost",
				GatewayPort: 8082,
				Port:        50432,
			},
			// Define Server fields as needed
		},
		Redis: &Redis{
			// Define Redis fields as needed
		},
		Cookie: &Cookie{
			// Define Cookie fields as needed
		},
	}
}
