# Changelog

All notable changes to DriveClean will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Rate limiting middleware (120 requests/minute per IP)
- File rename endpoint (`POST /api/files/rename`)
- File move endpoint (`POST /api/files/move`)
- Permission fix endpoint (`POST /api/files/permissions/fix`) - make files private
- Undo delete endpoint (`POST /api/files/undo-delete`) - restore recent deletions within 5 minutes
- Scan history endpoint (`GET /api/scan/history`) - track scan sessions
- Storage analytics endpoint (`GET /api/storage/analytics`) - file type, age, and size distributions
- Toast notification system replacing browser alerts
- Storage analytics modal with visual bar charts
- Keyboard shortcuts modal (press `?`)
- File rename action in file table
- "Make Private" bulk action for selected files
- Undo Delete button for recent deletions
- Docker support with multi-stage build (`Dockerfile`, `docker-compose.yml`)
- `prefers-reduced-motion` accessibility support
- Screen reader support with `aria-live` regions
- Fade-in animations for UI elements
- Additional file type icons (presentations, scripts, forms, drawings)
- 9 new test cases covering security headers, endpoints, and input validation

### Changed
- Scan history persisted to disk (`scan_history.json`)
- Improved file type icon coverage
- Toast notifications with auto-dismiss and manual close
- Enhanced keyboard shortcuts with `?` help

### Security
- Rate limiting on all endpoints
- CSP headers tightened
- Input validation on all new endpoints

## [2.0.0] - 2026-05-20

### Added
- Gmail cleanup (Promotions/Social categories)
- Google Photos scanning
- Folder-scoped scans
- Scan persistence across restarts
- WebSocket progress updates
- CSV/JSON/Print export
- Duplicate detection with MD5 checksums
- Bulk delete with progress modal
- Keyboard shortcuts
- Dark/light theme toggle
- Service Worker for offline caching
- GitHub Actions CI
- Render deployment support

### Changed
- Upgraded googleapis to v171
- Improved stale scan UX
- Hardened persistence layer
- Unified checks and session fallback

## [1.0.0] - 2026-04-15

### Added
- Initial release
- Google Drive scanning
- Duplicate finding
- Large/old/empty file detection
- Bulk delete to trash
- Empty trash
- Restore from trash
- Google OAuth authentication
- Session management with encrypted tokens
