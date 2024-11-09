package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	cache "github.com/NikoMalik/MemoryCache"
	"github.com/NikoMalik/yhwach/pkg/uuid"
)

const (
	REDIS_CACHE_TYPE  = "redis"
	MEMORY_CACHE_TYPE = "memory"
)

type Config struct {
	Account     *Account     `yaml:"account" mapstructure:"account" `
	Email       *Email       `yaml:"email" mapstructure:"email" `
	Database    *Database    `yaml:"database" mapstructure:"database" `
	Keys        *Keys        `yaml:"keys" mapstructure:"keys" `
	MFA         *MFA         `yaml:"mfa" mapstructure:"mfa" `
	SMTP        *SMTP        `yaml:"smtp" mapstructure:"smtp" `
	SecretKeys  *SecretKeys  `yaml:"secret_keys" mapstructure:"secret_keys" `
	ThirdParty  *ThirdParty  `yaml:"third_party" mapstructure:"third_party" `
	TLS         *TLS         `yaml:"tls" mapstructure:"tls" `
	Passsword   *Password    `yaml:"password" mapstructure:"password" `
	RateLimiter *RateLimiter `yaml:"rate_limit" mapstructure:"rate_limit" `
	Session     *Session     `yaml:"session" mapstructure:"session" `
	Admin       *Admin       `yaml:"admin" mapstructure:"admin" `
	Public      *Public      `yaml:"public" mapstructure:"public" `
	Server      *Server      `yaml:"server" mapstructure:"server" `
	Redis       *Redis       `yaml:"redis" mapstructure:"redis" `
	Cookie      *Cookie      `yaml:"cookie" mapstructure:"cookie" `

	AppAuthName string    `yaml:"app_auth_name" mapstructure:"app_auth_name" `
	Id          uuid.UUID `yaml:"id" mapstructure:"id" `
}

func (c *Config) Validate() error {
	if len(strings.TrimSpace(c.AppAuthName)) == 0 {
		return ErrAuthAppNameEmpty

	}

	var errs = [12]string{}
	var wg = new(sync.WaitGroup)

	validators := []func() error{
		c.Account.Validate,
		c.Email.Validate,
		c.Database.Validate,
		c.SMTP.Validate,
		c.TLS.Validate,
		c.MFA.Validate,
		c.Session.Validate, // include admin and public
		c.Cookie.Validate,
		c.Server.Validate,
		c.Redis.Validate,
		c.SecretKeys.Validate,
		c.RateLimiter.Validate,
	}

	for i, validate := range validators {
		wg.Add(1)
		go func(i int, validateFunc func() error) {
			defer wg.Done()
			if err := validateFunc(); err != nil {

				errs[i] = err.Error()

			}
		}(i, validate)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("validation errors: %v", errs)
	}

	return nil
}

// ---account config---
type Account struct {
	// `allow_deletion` determines whether users can delete their accounts.
	Password      *Password `yaml:"password" mapstructure:"password" `
	UserName      *UserName `yaml:"user_name" mapstructure:"user_name" `
	AllowDeletion bool      `yaml:"allow_deletion" mapstructure:"allow_deletion" `
	// `allow_signup` determines whether users are able to create new accounts.
	AllowSignup bool `yaml:"allow_signup" mapstructure:"allow_sigup" `
	BanIp       bool `yaml:"ban_ip" mapstructure:"ban_ip" `
	BanEmail    bool `yaml:"ban_email" mapstructure:"ban_email" `
}

func (a *Account) Validate() error {
	if a.Password.Enabled {
		if a.Password.MinLength > a.Password.MaxLength {
			return ErrPasswordMaxLengthLessThanMinLength
		}

		if a.Password.MinLength < 2 {
			return ErrPasswordMinLengthLessThan_2
		}

		if a.Password.MaxLength < 6 {
			return ErrPasswordMaxLengthLessThan_6
		}

		if a.Password.Power == "" {
			return ErrPasswordPowerEmpty
		}
	}

	if a.UserName.Enabled {
		if a.UserName.MinLength > a.UserName.MaxLength {
			return ErrUserNameMaxLengthLessThanMinLength
		}

		if a.UserName.MinLength < 2 {
			return ErrUserNameMinLengthLessThan_2
		}

	}

	return nil

}

type UserName struct {
	MaxLength int `yaml:"max_length"`

	MinLength int `yaml:"min_length"`

	AcquireOnLogin        bool `yaml:"acquire_on_login"`
	AcquireOnRegistration bool `yaml:"acquire_on_registration" `
	Enabled               bool `yaml:"enabled" mapstructure:"enabled" `
	UseAsLoginIdentifier  bool `yaml:"use_as_login_identifier" mapstructure:"use_as_login_identifier" `
}

type Password struct {
	Special        string `mapstructure:"special" `
	Power          string `mapstructure:"power" `
	MinLength      int    `mapstructure:"min_length" `
	MaxLength      int    `mapstructure:"max_length" `
	AcquireLogin   bool   `mapstructure:"acquire_login" `
	AcquireRegistr bool   `mapstructure:"acquire_registration" `
	Recovery       bool   `mapstructure:"recovery" `
	Enabled        bool   `mapstructure:"enabled" `
}

// ---smtp config---
type Email struct {
	SMTP_SERV            *SMTP  `yaml:"smtp" mapstructure:"smtp" `
	FromAddress          string `yaml:"from" mapstructure:"from_address" `
	FromName             string `yaml:"from_name" mapstructure:"from_name" `
	Limit                int    `yaml:"limit" mapstructure:"limit" `
	Length               int    `yaml:"length" mapstructure:"length" `
	MaxNumberofEmail     int    `yaml:"max_number_of_email" mapstructure:"max_number_of_email" `
	RecquireVerification bool   `yaml:"recquire_verification" mapstructure:"recquire_verification" `
	EmailAsLogin         bool   `yaml:"email_as_login" mapstructure:"email_as_login" `
	AcquireEmail         bool   `yaml:"acquire_email" mapstructure:"acquire_email" `
	AcquireRegistr       bool   `yaml:"acquire_registr" mapstructure:"acquire_registr" `
	AcquireLogin         bool   `yaml:"acquire_login" mapstructure:"acquire_login" `
	Enable_Delivery      bool   `yaml:"enable" mapstructure:"enable" `
}

func (e *Email) Validate() error {
	if e.Enable_Delivery {
		if len(strings.TrimSpace(e.FromAddress)) == 0 {
			return ErrFromAddressEmpty
		}
		if len(strings.TrimSpace(e.FromName)) == 0 {
			return ErrFromNameEmpty
		}
		if len(strings.TrimSpace(e.SMTP_SERV.Host)) == 0 {
			return ErrHostEmptySmtp
		}
		if e.SMTP_SERV.Port == 0 {
			return ErrPortEmptySmtp
		}
		if len(strings.TrimSpace(e.SMTP_SERV.User)) == 0 {
			return ErrUserEmptySmtp
		}
		if len(strings.TrimSpace(e.SMTP_SERV.Password)) == 0 {
			return ErrPasswordEmptySmtp
		}
	}
	return nil
}

type SMTP struct {
	Host     string `mapstructure:"host" `
	User     string `mapstructure:"user" `
	Password string `mapstructure:"password" `
	Port     int    `mapstructure:"port" `
}

func (s *SMTP) Validate() error {
	if len(strings.TrimSpace(s.Host)) == 0 {
		return ErrHostEmptySmtp
	}
	if s.Port == 0 {
		return ErrPortEmptySmtp
	}
	if len(strings.TrimSpace(s.User)) == 0 {
		return ErrUserEmptySmtp
	}
	if len(strings.TrimSpace(s.Password)) == 0 {
		return ErrPasswordEmptySmtp
	}
	return nil
}

// ---database config---
type Database struct {
	Dialect  string `mapstructure:"dialect" `
	Host     string `mapstructure:"host" `
	Port     int    `mapstructure:"port" `
	User     string `mapstructure:"user" `
	Password string `mapstructure:"password" `
	Name     string `mapstructure:"name" `
	SSLMode  string `mapstructure:"sslmode" `
	Url      string `mapstructure:"url" `
}

func (d *Database) Validate() error {
	if len(strings.TrimSpace(d.Url)) > 0 {
		return nil
	}
	if len(strings.TrimSpace(d.Name)) == 0 {
		return ErrDatabaseEmpty
	}
	if len(strings.TrimSpace(d.User)) == 0 {
		return ErrUsernameEmpty
	}
	if len(strings.TrimSpace(d.Host)) == 0 {
		return ErrHostEmpty
	}
	if d.Port == 0 {
		return ErrPortEmpty
	}
	if len(strings.TrimSpace(d.Dialect)) == 0 {
		return ErrDialectEmpty
	}
	return nil
}

// ---mfa config---

type Keys struct {
	Token     string `yaml:"token" mapstructure:"token" `
	UserVerif string `yaml:"user_verif" mapstructure:"user_verif" `
	Limit     int    `yaml:"limit" mapstructure:"limit" `
	Enabled   bool   `yaml:"enabled" mapstructure:"enabled" `
}

type TOTP struct {
	Skew    int  `yaml:"skew" mapstructure:"skew" `
	Enabled bool `yaml:"enabled" mapstructure:"enabled" `
}

func (t *TOTP) Validate() error {
	// Assuming additional checks are needed for TOTP
	if t.Enabled && t.Skew < 0 {
		return ErrSkewInvalid
	}
	return nil
}

type OTP struct {
	Secret  string `mapstructure:"secret" `
	Skew    int    `mapstructure:"skew" `
	Digits  int    `mapstructure:"digits" `
	Period  int    `mapstructure:"period" `
	Enabled bool   `mapstructure:"enabled" `
}

type Provider struct {
	Name     string `mapstructure:"name"`
	ClientID string `mapstructure:"client_id"`
	Secret   string `mapstructure:"secret"`
	Enabled  bool   `mapstructure:"enabled"`
}

type Providers struct {
	Github   *Provider `yaml:"github" mapstructure:"github" `
	Google   *Provider `yaml:"google" mapstructure:"google" `
	Facebook *Provider `yaml:"facebook" mapstructure:"facebook" `
	Twitter  *Provider `yaml:"twitter" mapstructure:"twitter" `
}

type ThirdParty struct {
	noCopy              NoCopy
	Providers           *Providers `yaml:"providers" mapstructure:"providers" `
	AllowedRedirectUrls []string   `yaml:"allowed_redirect_url" mapstructure:"allowed_redirect_url" `
	RedirectUrl         string     `yaml:"redirect_url" mapstructure:"redirect_url" `
	DefaultRedirectUrl  string     `yaml:"default_redirect_url" mapstructure:"default_redirect_url" `
	Enabled             bool       `yaml:"enabled" mapstructure:"enabled" `
}

func (t *ThirdParty) Validate() error {
	if t.Enabled {

		if t.RedirectUrl == "" && t.DefaultRedirectUrl == "" {
			return ErrThirdPartyRedirectUrlEmpty
		}
		if len(t.AllowedRedirectUrls) == 0 {
			return ErrAllowedRedirectUrlsEmpty
		}

		if t.DefaultRedirectUrl != "" {
			t.AllowedRedirectUrls = append(t.AllowedRedirectUrls, t.DefaultRedirectUrl)
		}

		for _, url := range t.AllowedRedirectUrls {
			if url == "" {
				return ErrAllowedRedirectUrlsEmpty
			}
			if strings.HasSuffix(url, "/") {
				return ErrAllowedRedirectUrlSuffix
			}
		}
		if err := t.Providers.Validate(); err != nil {
			return fmt.Errorf("providers validation failed: %w", err)
		}
	}
	return nil
}

func (p *Providers) Validate() error {
	providers := []*Provider{p.Github, p.Google, p.Facebook, p.Twitter}
	for _, provider := range providers {
		if provider.Enabled {
			if err := provider.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Provider) Validate() error {
	if p.ClientID == "" || p.Secret == "" {
		return ErrProviderCredentialsEmpty
	}
	return nil
}

type MFA struct {
	OTP            *OTP        `yaml:"otp" mapstructure:"otp" `
	Keys           *Keys       `yaml:"keys" mapstructure:"keys" ` // configure settings for mfa
	TOTP           *TOTP       `yaml:"totp" mapstructure:"totp" `
	ThirdParty     *ThirdParty `yaml:"third_party" mapstructure:"third_party" `
	AcquireLogin   bool        `yaml:"acquire_login" mapstructure:"acquire_login" `
	AcquireRegistr bool        `yaml:"acquire_registr" mapstructure:"acquire_registr" `
	MultiFactor    bool        `yaml:"multi_factor" mapstructure:"multi_factor" `
	Email          bool        `yaml:"email" mapstructure:"email" `
}

func (o *OTP) Validate() error {
	if o.Enabled {
		if o.Secret == "" {
			return ErrOtpSecretEmpty
		}
		if o.Digits < 4 || o.Digits > 8 {
			return ErrDigitsInvalid
		}
		if o.Period <= 0 {
			return ErrPeriodInvalid
		}
	}
	return nil
}

func (m *MFA) Validate() error {

	if m.ThirdParty.Enabled {
		if err := m.ThirdParty.Validate(); err != nil {
			return fmt.Errorf("third party validation failed: %w", err)
		}
	}

	if m.Email && !m.MultiFactor {
		return ErrEmailRequired
	}

	if err := m.OTP.Validate(); err != nil {
		return fmt.Errorf("OTP validation failed: %w", err)
	}

	if err := m.TOTP.Validate(); err != nil {
		return fmt.Errorf("TOTP validation failed: %w", err)
	}

	return nil
}

//---RATE LIMITER CONFIG---

type RateLimit struct {
	Interval time.Duration `yaml:"interval" mapstructure:"interval" `
	Tokens   uint64        `yaml:"tokens" mapstructure:"tokens" `
}

type RateLimiter struct {
	PasscodeLimit *RateLimit `yaml:"passcode_limit" mapstructure:"passcode_limit" `
	OtpLimit      *RateLimit `yaml:"otp_limit" mapstructure:"otp_limit" `
	TokenLimits   *RateLimit `yaml:"token_limits" mapstructure:"token_limits" `
	Redis_Cache   *Cache     `yaml:"redis" mapstructure:"redis" `
	Memory_Cache  *Cache     `yaml:"memory" mapstructure:"memory" `
	Cache_Type    string     `yaml:"cache_type" mapstructure:"cache_type" `
	Enabled       bool       `yaml:"enabled" mapstructure:"enabled" `
}

type Cache struct {
	noCopy       NoCopy
	Redis_Cache  *Redis `yaml:"redis" mapstructure:"redis" `
	Memory_Cache *cache.Cache[string, any]
}

func (r *RateLimiter) Validate() error {

	if r.Enabled {

		if r.PasscodeLimit.Interval == 0 {
			return ErrIntervalEmpty
		}
		if r.PasscodeLimit.Tokens == 0 {
			return ErrTokensEmpty
		}
		if r.OtpLimit.Interval == 0 {
			return ErrIntervalEmpty
		}
		if r.OtpLimit.Tokens == 0 {
			return ErrTokensEmpty
		}
		if r.TokenLimits.Interval == 0 {
			return ErrIntervalEmpty
		}
		if r.TokenLimits.Tokens == 0 {
			return ErrTokensEmpty
		}

		switch r.Cache_Type {
		case REDIS_CACHE_TYPE:
			if r.Redis_Cache == nil {
				return ErrRedisCacheEmpty
			}
			if err := r.Redis_Cache.Redis_Cache.Validate(); err != nil {
				return fmt.Errorf("redis cache validation failed: %w", err)
			}
		case MEMORY_CACHE_TYPE:
			if r.Memory_Cache == nil {
				return ErrMemoryCacheEmpty
			}
		default:
			return ErrCacheTypeInvalid
		}
	}

	return nil
}

// ---TLS CONFIG---

type TLS struct {
	KeyPath  string `yaml:"key_path" mapstructure:"key_path" `
	CertPath string `yaml:"cert_path" mapstructure:"cert_path" `
	CAPath   string `yaml:"ca_path" mapstructure:"ca_path" `
	Key      []byte
	//Certificate for the TLS connection (CertPath will this overwrite, if specified)
	Cert    []byte
	Enabled bool `yaml:"enabled" mapstructure:"enabled" `
}

func (t *TLS) Validate() error {
	if len(t.KeyPath) == 0 {
		return ErrKeyPathEmpty
	}
	if len(t.CertPath) == 0 {
		return ErrCertPathEmpty
	}
	if len(t.CAPath) == 0 {
		return ErrCAPathEmpty
	}

	if len(t.Key) == 0 {
		data, err := os.ReadFile(t.KeyPath)
		if err != nil {
			return err
		}
		t.Key = data
	}
	if len(t.Cert) == 0 {
		data, err := os.ReadFile(t.CertPath)
		if err != nil {
			return err
		}
		t.Cert = data
	}

	return nil
}

func (t *TLS) Config() (_ *tls.Config, err error) {
	if !t.Enabled {
		return nil, nil
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}

// ---KEYS DECRYPT JWT---

type SecretKeys struct {
	Keys []string `yaml:"keys" mapstructure:"keys" `
}

func (s *SecretKeys) Validate() error {
	if len(s.Keys) == 0 {
		return ErrKeysEmpty
	}
	return nil
}

// ---GRPC CONFIG---

type GRPC struct {
	CustomHeaders []string `yaml:"custom_headers" mapstructure:"custom_headers" `
	GRPCEndpoint  string   `yaml:"grpc_endpoint" mapstructure:"grpc_endpoint" `
	Host          string   `yaml:"host" mapstructure:"host" `

	GatewayPort    int  `yaml:"gateway_port" mapstructure:"gateway_port" `
	Port           int  `yaml:"server_port" mapstructure:"server_port" `
	GatewayEnabled bool `yaml:"gateway_enabled" mapstructure:"gateway_enabled" `
}

func (g *GRPC) Validate() error {

	if g.GatewayEnabled {

		if g.GatewayPort == 0 {
			return ErrGatewayPortEmptyGrpc
		}
	}
	return nil
}

// ---Redis CONFIG---

type Redis struct {
	Host     string        `mapstructure:"host"`
	Port     string        `mapstructure:"port"`
	Username string        `mapstructure:"username"`
	Password string        `mapstructure:"password"`
	Dial     time.Duration `mapstructure:"dialTimeout"`
	Idle     time.Duration `mapstructure:"idleTimeout"`
	Option   bool          `mapstructure:"option"`
}

func (r *Redis) Validate() error {

	if len(r.Host) == 0 {
		return ErrRedisHostEmpty
	}
	if len(r.Port) == 0 {
		return ErrRedisPortEmpty
	}

	if len(strings.TrimSpace(r.Username)) == 0 {
		return ErrRedisUsernameEmpty
	}

	if len(strings.TrimSpace(r.Password)) == 0 {
		return ErrRedisPasswordEmpty
	}

	if r.Option {
		if r.Dial == 0 {
			return ErrRedisDialEmpty
		}
		if r.Idle == 0 {
			return ErrRedisIdleEmpty
		}
	}

	return nil
}

//---SERVER CONFIG---

type Server struct {
	GRPC *GRPC `mapstructure:"grpc"`
}

type ServerSettings struct {
	Host string   `mapstructure:"address"`
	Port int      `mapstructure:"port"`
	Cors []string `mapstructure:"cors"`
}

func (s *Server) Validate() error {
	err := s.GRPC.Validate()
	if err != nil {
		return fmt.Errorf("error validating grpc settings: %w", err)
	}
	err = s.ServerSettings.Validate()
	if err != nil {
		return fmt.Errorf("error validating public server settings: %w", err)
	}
	for i := range s.ServerSettings.Cors {
		if s.ServerSettings.Cors[i] == "*" {
			return ErrUnsafeCors
		}
	}
	return nil
}

func (s *ServerSettings) Validate() error {
	if len(strings.TrimSpace(s.Host)) == 0 {
		return ErrPublicAddressEmpty
	}
	if s.Port == 0 {
		return ErrPublicPortEmpty
	}

	return nil
}

// ---SESSION CONFIG---

type Session struct {
	Cookie                        *Cookie       `yaml:"cookie" mapstructure:"cookie" `
	Issuer                        string        `yaml:"issuer" mapstructure:"issuer" `
	MaxAge                        time.Duration `yaml:"max_age" mapstructure:"max_age" `
	Life                          time.Duration `yaml:"life" mapstructure:"life" `
	Limit                         int           `yaml:"limit" mapstructure:"limit" `
	Enabled                       bool          `yaml:"enabled" mapstructure:"enabled" `
	EnableAuthHeader_X_AUTH_TOKEN bool          `yaml:"enable_auth_header_x_auth_token" mapstructure:"enable_auth_header_x_auth_token" `
}

type Cookie struct {
	Domain   string `yaml:"domain" mapstructure:"domain" `
	Name     string `yaml:"name" mapstructure:"name" `
	HttpOnly bool   `yaml:"http_only" `
	Secure   bool   `yaml:"secure"`
}

func (s *Session) Validate() error {
	if len(strings.TrimSpace(s.Issuer)) == 0 {
		return ErrIssuerEmpty
	}
	if s.MaxAge == 0 {
		return ErrMaxAgeEmpty
	}
	if s.Life == 0 {
		return ErrLifeEmpty
	}
	if s.Limit == 0 {
		return ErrLimitEmpty
	}
	return nil
}

func (s *Cookie) Validate() error {
	if len(strings.TrimSpace(s.Name)) == 0 {
		return ErrCookieNameEmpty
	}
	return nil
}
