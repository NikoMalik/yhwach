package config

import (
	"sync"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

var stringBufferPool = &sync.Pool{
	New: func() interface{} {
		return lowlevelfunctions.NewStringBuffer(64)
	},
}

const (
	// ANSI escape codes for colors
	Reset  = "\033[0m"
	Red    = "\033[31m" // Red color
	Green  = "\033[32m" // Green color
	Yellow = "\033[33m" // Yellow color
)

type ConfigError struct {
	Field string
	Msg   string
}

func (e ConfigError) Error() string {
	var s = stringBufferPool.Get().(*lowlevelfunctions.StringBuffer)
	s.Reset()
	s.WriteString(Red + e.Field + Reset)
	s.WriteString(": ")
	s.WriteString(Green + e.Msg + Reset)
	stringBufferPool.Put(s)
	return s.String()
}

var (
	ErrInvalidConfig                      = ConfigError{Field: "config", Msg: "invalid config"}
	ErrAuthAppNameEmpty                   = ConfigError{Field: "config", Msg: "app name must not be empty"}
	ErrInvalidDatabaseConfig              = ConfigError{Field: "database", Msg: "invalid database config"}
	ErrDatabaseEmpty                      = ConfigError{Field: "database", Msg: "database name must not be empty"}
	ErrUsernameEmpty                      = ConfigError{Field: "database", Msg: "username must not be empty"}
	ErrHostEmpty                          = ConfigError{Field: "database", Msg: "host must not be empty"}
	ErrPortEmpty                          = ConfigError{Field: "database", Msg: "port must not be empty"}
	ErrDialectEmpty                       = ConfigError{Field: "database", Msg: "dialect must not be empty"}
	ErrHostEmptySmtp                      = ConfigError{Field: "smtp", Msg: "host must not be empty"}
	ErrPortEmptySmtp                      = ConfigError{Field: "smtp", Msg: "port must not be empty"}
	ErrUserEmptySmtp                      = ConfigError{Field: "smtp", Msg: "user must not be empty"}
	ErrPasswordEmptySmtp                  = ConfigError{Field: "smtp", Msg: "password must not be empty"}
	ErrTokenEmpty                         = ConfigError{Field: "mfa", Msg: "token must not be empty"}
	ErrUserVerifEmpty                     = ConfigError{Field: "mfa", Msg: "user verification must not be empty"}
	ErrLimitEmpty                         = ConfigError{Field: "mfa", Msg: "limit must not be empty"}
	ErrSecretEmpty                        = ConfigError{Field: "mfa", Msg: "secret must not be empty"}
	ErrDigitsEmpty                        = ConfigError{Field: "mfa", Msg: "digits must not be empty"}
	ErrPeriodEmpty                        = ConfigError{Field: "mfa", Msg: "period must not be empty"}
	ErrSkewEmpty                          = ConfigError{Field: "mfa", Msg: "skew must not be empty"}
	ErrKeyPathEmpty                       = ConfigError{Field: "tls", Msg: "key path must not be empty"}
	ErrCertPathEmpty                      = ConfigError{Field: "tls", Msg: "cert path must not be empty"}
	ErrCAPathEmpty                        = ConfigError{Field: "tls", Msg: "ca path must not be empty"}
	ErrIntervalEmpty                      = ConfigError{Field: "rate limiter", Msg: "interval must not be empty"}
	ErrTokensEmpty                        = ConfigError{Field: "rate limiter", Msg: "token must not be empty"}
	ErrKeysEmpty                          = ConfigError{Field: "secret keys", Msg: "keys must not be empty"}
	ErrPublicAddressEmpty                 = ConfigError{Field: "public address", Msg: "public address must not be empty"}
	ErrPublicPortEmpty                    = ConfigError{Field: "public port", Msg: "public port must not be empty"}
	ErrAdminAddressEmpty                  = ConfigError{Field: "admin address", Msg: "admin address must not be empty"}
	ErrAdminPortEmpty                     = ConfigError{Field: "admin port", Msg: "admin port must not be empty"}
	ErrUnsafeCors                         = ConfigError{Field: "cors", Msg: "cors must not be empty"}
	ErrIssuerEmpty                        = ConfigError{Field: "session", Msg: "issuer must not be empty"}
	ErrMaxAgeEmpty                        = ConfigError{Field: "session", Msg: "max age must not be empty"}
	ErrLifeEmpty                          = ConfigError{Field: "session", Msg: "life must not be empty"}
	ErrLimitEmptySession                  = ConfigError{Field: "session", Msg: "limit must not be empty"}
	ErrCookieNameEmpty                    = ConfigError{Field: "cookie", Msg: "name must not be empty"}
	ErrSkewInvalid                        = ConfigError{Field: "session", Msg: "skew must not be empty"}
	ErrSecretInvalid                      = ConfigError{Field: "session", Msg: "secret must not be empty"}
	ErrThirdPartyAuthEmpty                = ConfigError{Field: "third party auth", Msg: "third party auth must not be empty"}
	ErrThirdPartyAuthSecretEmpty          = ConfigError{Field: "third party auth", Msg: "third party auth secret must not be empty"}
	ErrThirdPartyAuthURLEmpty             = ConfigError{Field: "third party auth", Msg: "third party auth url must not be empty"}
	ErrThirdPartyRedirectUrlEmpty         = ConfigError{Field: "third party auth", Msg: "third party redirect url must not be empty"}
	ErrAllowedRedirectUrlsEmpty           = ConfigError{Field: "third party auth", Msg: "allowed domains must not be empty"}
	ErrAllowedRedirectUrlSuffix           = ConfigError{Field: "third party auth", Msg: "allowed domains suffix must not be /"}
	ErrProviderCredentialsEmpty           = ConfigError{Field: "third party auth", Msg: "provider credentials must not be empty"}
	ErrPeriodInvalid                      = ConfigError{Field: "mfa/otp", Msg: "period invalid "}
	ErrOtpSecretEmpty                     = ConfigError{Field: "mfa/otp", Msg: "secret must not be empty"}
	ErrDigitsInvalid                      = ConfigError{Field: "mfa/otp", Msg: "digits invalid "}
	ErrEmailRequired                      = ConfigError{Field: "mfa/email", Msg: "email is required"}
	ErrProviderInvalid                    = ConfigError{Field: "mfa", Msg: "provider invalid"}
	ErrFromAddressEmpty                   = ConfigError{Field: "email", Msg: "from address must not be empty"}
	ErrFromNameEmpty                      = ConfigError{Field: "email", Msg: "from name must not be empty"}
	ErrPasswordMaxLengthLessThanMinLength = ConfigError{Field: "account", Msg: "password max length must not be less than min length"}
	ErrPasswordMinLengthLessThan_2        = ConfigError{Field: "account", Msg: "password min length must not be less than 2"}
	ErrPasswordMaxLengthLessThan_6        = ConfigError{Field: "account", Msg: "password max length must not be less than 6"}
	ErrPasswordPowerEmpty                 = ConfigError{Field: "account", Msg: "password power must not be empty"}
	ErrRedisHostEmpty                     = ConfigError{Field: "redis", Msg: "host must not be empty"}
	ErrRedisPortEmpty                     = ConfigError{Field: "redis", Msg: "port must not be empty"}
	ErrRedisPasswordEmpty                 = ConfigError{Field: "redis", Msg: "password must not be empty"}
	ErrRedisUsernameEmpty                 = ConfigError{Field: "redis", Msg: "username must not be empty"}
	ErrRedisDialEmpty                     = ConfigError{Field: "redis", Msg: "dial must not be empty"}
	ErrRedisIdleEmpty                     = ConfigError{Field: "redis", Msg: "idle must not be empty"}
	ErrHostEmptyGrpc                      = ConfigError{Field: "grpc", Msg: "host must not be empty"}
	ErrServerPortEmptyGrpc                = ConfigError{Field: "grpc", Msg: "port must not be empty"}
	ErrGatewayPortEmptyGrpc               = ConfigError{Field: "grpc", Msg: "gateway port must not be empty"}
	ErrUserNameMaxLengthLessThanMinLength = ConfigError{Field: "account", Msg: "username max length must not be less than min length"}
	ErrUserNameMinLengthLessThan_2        = ConfigError{Field: "account", Msg: "username min length must not be less than 2"}
	ErrRedisCacheEmpty                    = ConfigError{Field: "redis", Msg: "redis cache must not be empty"}
	ErrMemoryCacheEmpty                   = ConfigError{Field: "memory", Msg: "memory cache must not be empty: pls init memory cache with string/any"}
	ErrCacheTypeInvalid                   = ConfigError{Field: "cache type", Msg: "cache type must be memory or redis"}
)
