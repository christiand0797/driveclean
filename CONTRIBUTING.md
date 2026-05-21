# Contributing to DriveClean

Thank you for your interest in contributing! DriveClean is an open source Google Drive cleanup app.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/driveclean.git`
3. Install dependencies: `npm ci`
4. Create a `.env` file from `.env.example`
5. Start the server: `npm start`
6. Run tests: `npm test`

## Development Workflow

```bash
# Run syntax checks and tests
npm run check

# Start server with auto-restart (install nodemon first)
npm install -g nodemon
nodemon server.js

# Run tests in watch mode
npm test -- --watch
```

## Code Style

- Use 2-space indentation
- Single quotes for strings
- Semicolons at end of statements
- No trailing commas in objects/arrays
- Follow existing patterns in the codebase

## Pull Request Process

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Run `npm run check` to ensure all tests pass
4. Commit with a descriptive message
5. Push to your fork
6. Open a Pull Request

## Testing

- All new features should have corresponding tests
- Tests are in the `tests/` directory
- Use Node.js built-in test runner (`node:test`)
- Smoke tests verify server boots and endpoints respond correctly

### Adding Tests

```javascript
const test = require('node:test');
const assert = require('node:assert/strict');

test('my new feature works', async (t) => {
  const { port } = await startServer(t);
  const response = await fetch(`http://127.0.0.1:${port}/api/my-endpoint`);
  assert.equal(response.status, 200);
});
```

## Docker Development

```bash
# Build and run with Docker
docker compose up --build

# Run tests in container
docker compose run driveclean npm test
```

## API Documentation

See the API section in README.md for endpoint documentation.

## Reporting Issues

- Use GitHub Issues
- Include steps to reproduce
- Include environment details (Node version, OS)
- For security issues, email the maintainer directly

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
