# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands
- Build: `make build/%target%` - Build specific commands
- Test: `make test` - Run all tests with race detection
- Single test: `GO_TEST_FUNC='TestName' make test` - Run a specific test function
- Coverage: `make coverage` - Generate test coverage report
- Lint: `make lint` - Run all linters via golangci-lint
- Format code: `make fmt` - Format code with goimportz and gofumpt

## Code style
- **Imports**: Group imports (stdlib, 3rd-party, local) with blank lines between groups
- **JSON**: Use bytedance/sonic for JSON serialization instead of encoding/json
- **Logging**: Use log/slog instead of other logging libraries
- **Observability**: All operations should include OpenTelemetry tracing, metrics, and logging
- **Error handling**: Always use `fmt.Errorf("some context: %w", err)` for wrapping errors
- **Function naming**: Use PascalCase for exported funcs, camelCase for internal funcs
- **Line length**: Keep lines under 200 characters
- **Variable naming**: Descriptive names, avoid single-letter names except for common cases (i, err)
- **Comments**: Every exported type and function must have a documentation comment
- **Newlines**: Ensure all files have a newline at the end

## Design principles
- Prefer composition over inheritance
- Design for testability and modularity
- Follow Go idioms and conventions (use interfaces, error handling patterns)
- Be mindful of performance with large-scale deployments in mind

## Testing
- Use github.com/google/go-cmp for assertions in tests
- Avoid using testify/assert and testify/require  
- For test mocking, consider implementing custom mock objects or use a different mocking framework
- The migration from testify to go-cmp is in progress
