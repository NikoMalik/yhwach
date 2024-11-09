package config

type Void struct{}

type NoCopy struct{}

func (*NoCopy) Lock(_ ...Void)   {}
func (*NoCopy) Unlock(_ ...Void) {}
