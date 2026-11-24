# Changelog

## [0.14.2](https://github.com/unified-systems-com/github-core-tap/compare/v0.14.1...v0.14.2) (2026-11-24)


### Features

* declare event time for every model (tap v0.4.7) ([deaa804](https://github.com/unified-systems-com/github-core-tap/commit/deaa804d4ee196157e6458e4477170dbab8e9179))
* declare event time for every model (tap v0.4.7) ([3942027](https://github.com/unified-systems-com/github-core-tap/commit/39420275e0bcb09b8b8fb2269e7e43f92fad1afb))

## [0.14.1](https://github.com/unified-systems-com/github-core-tap/compare/v0.14.0...v0.14.1) (2026-11-16)


### Features

* declare Dimension nodes for this plugin's dimension keys ([ceb8c2d](https://github.com/unified-systems-com/github-core-tap/commit/ceb8c2d4d1f6d470767c67da9a4080cb42b67af9))
* declare Dimension nodes for this plugin's dimension keys (github.observation, github.surface) ([28e3801](https://github.com/unified-systems-com/github-core-tap/commit/28e380156f7d3bcd9edddc48e22a5f57ced1bc52))
* declare github.owner and github.repo; run against core main's dimension storage ([24ac396](https://github.com/unified-systems-com/github-core-tap/commit/24ac396d3682311f965f7f1373b7ec5c8cdfee15))
* **sbom:** GROUP NULLS - write an observed CVSS, SSVC, KEV or EPSS group whole, members with no value as None ([#240](https://github.com/unified-systems-com/github-core-tap/issues/240)) ([05d8ac3](https://github.com/unified-systems-com/github-core-tap/commit/05d8ac3d662c78f6509f816c9c8654722ffe17e7))


### Bug Fixes

* **ci-record:** pin git_core v0.1.2 and compliance_core v0.8.12, the releases that carry their Dimension seeds ([a820487](https://github.com/unified-systems-com/github-core-tap/commit/a820487c81f89f665d0d73c3207d43520a2fa68d))
* **collector:** the readiness line reports the scope the run walked [via demo-dev] ([d919afe](https://github.com/unified-systems-com/github-core-tap/commit/d919afed582d2e8d4387ce862a4bdb4b9557d6ff))


### Documentation

* **vocabulary:** backlog audit_log_event, blocked on Enterprise Cloud tier ([a797184](https://github.com/unified-systems-com/github-core-tap/commit/a797184e4b5706849a14c4e9132e252bfe3fc80d))

## [0.12.2](https://github.com/unified-systems-com/tap-plugin-github-core/compare/v0.12.1...v0.12.2) (2026-09-26)


### Bug Fixes

* **ci:** drop the nightly's latest-release row; run vs core main only [via bom-bom] ([b58d6e5](https://github.com/unified-systems-com/tap-plugin-github-core/commit/b58d6e501720ab204732b65f5b09adbb0ff91dc2))
* **ci:** drop the nightly's latest-release row; the nightly runs vs core main only ([3493379](https://github.com/unified-systems-com/tap-plugin-github-core/commit/34933790120b60cf16b118da163deb46fbce244f))
