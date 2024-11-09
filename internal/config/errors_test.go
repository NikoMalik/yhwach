package config

import (
	"fmt"
	"testing"
)

func TestConfigError(t *testing.T) {
	fmt.Println(ErrInvalidConfig.Error())

	fmt.Println(ErrInvalidConfig)

}
