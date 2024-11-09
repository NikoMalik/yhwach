build:
	@go build -o ./bin/yhwach ./cmd/main.go


run: build 
	@./bin/yhwach
