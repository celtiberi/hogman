# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `REVIEW.md` documenting project review findings, DNS/Cloudflare operational notes, and security rationale.

## [Baseline] - 2026-11-19

### Added
- Core Hogman stack (`core/`): Headscale, Caddy edge and portal, CoreDNS, `step-ca` with name-constrained root and intermediate CAs, `registrar` service/CLI, `hogman-join` tool with native Tailscale and embedded `tsnet` side-by-side mode, and local end-to-end test suite (`core/test/run.sh`).
- Project website (`site/`) deployed to Fly.io and served on `hogman.network`.
- Architecture and design specification (`DESIGN.md`).
