# Changelog

## [0.7.0](https://github.com/koki-develop/ghasec/compare/v0.6.1...v0.7.0) (2026-03-29)


### Features

* add unpinned-container rule to enforce digest-pinned container images ([7ad6d50](https://github.com/koki-develop/ghasec/commit/7ad6d5020e035a72d3eb8b6d93834290c64bff06))
* enforce digest pinning for docker actions in unpinned-action rule ([10f8a8f](https://github.com/koki-develop/ghasec/commit/10f8a8fd33814c921d918298532eea38fc0fdf9b))


### Patches

* sort map iterations in code generator for deterministic output ([517d2fc](https://github.com/koki-develop/ghasec/commit/517d2fcfae0701a6bb3710b7afb365687cbd69c2))
* validate sha256 digest format in unpinned-container rule ([2ff2495](https://github.com/koki-develop/ghasec/commit/2ff24953c8068d7f1e92362167246c4a823b0453))

## [0.6.1](https://github.com/koki-develop/ghasec/compare/v0.6.0...v0.6.1) (2026-03-27)


### Patches

* update E2E expectation for schedule cron required validation ([63aace4](https://github.com/koki-develop/ghasec/commit/63aace41e59e408606f79580ac803703a81e09a2))
* update SchemaStore submodule and regenerate workflow validation ([8c26252](https://github.com/koki-develop/ghasec/commit/8c262525744d6ef6e2ac7cef1b98db8cfa9b1ff4))

## [0.6.0](https://github.com/koki-develop/ghasec/compare/v0.5.0...v0.6.0) (2026-03-26)


### Features

* add update notification for new releases ([51f5b43](https://github.com/koki-develop/ghasec/commit/51f5b437e3699c0405d62c27b927fb8e9a5ba426))

## [0.5.0](https://github.com/koki-develop/ghasec/compare/v0.4.0...v0.5.0) (2026-03-26)


### Features

* add actor-bot-check rule and expression AST support ([204d9ed](https://github.com/koki-develop/ghasec/commit/204d9ed2e7b0f49969ab77319e0c0e1f2f434ae6))
* add secrets-inherit rule ([01786a6](https://github.com/koki-develop/ghasec/commit/01786a60ca23ee02e73ac75ff05221644f8fc262))

## [0.4.0](https://github.com/koki-develop/ghasec/compare/v0.3.0...v0.4.0) (2026-03-26)


### Features

* rename --format agent to --format markdown and add Ref links ([fe325fd](https://github.com/koki-develop/ghasec/commit/fe325fdbfb34bd8b427ff1a21a0a95cbaa3548d1))

## [0.3.0](https://github.com/koki-develop/ghasec/compare/v0.2.0...v0.3.0) (2026-03-25)


### Features

* add --format agent for AI-agent-friendly Markdown output ([7d684d7](https://github.com/koki-develop/ghasec/commit/7d684d7adfc9f43acd77797d47bce454f6da0aaa))
* add agent format support for dangerous-checkout rule ([e78bc2a](https://github.com/koki-develop/ghasec/commit/e78bc2a7f942112672c45f4ac33dc21fbc842dfd))
* add deprecated-commands rule ([85d22e2](https://github.com/koki-develop/ghasec/commit/85d22e2dbf0fe9de2d4dc039f9f3d50d346f316b))

## [0.2.0](https://github.com/koki-develop/ghasec/compare/v0.1.0...v0.2.0) (2026-03-25)


### Features

* add dangerous-checkout rule ([c3ed192](https://github.com/koki-develop/ghasec/commit/c3ed192f199fbdcc5244d8aab08f723e1b88e1ce))
* add file:line:col prefix to github-actions format messages ([16b7e37](https://github.com/koki-develop/ghasec/commit/16b7e3718adaedda5689c0e67df232587e438fcb))
* add progress bar for real-time linting progress ([338cd36](https://github.com/koki-develop/ghasec/commit/338cd369da71939fa711b1cabf9adf8f53c19cdf))
* add rich summary output with colors and icons ([b57ae9c](https://github.com/koki-develop/ghasec/commit/b57ae9c07a1fba8477abdd17f5828e217061ee09))
* show hint to set GITHUB_TOKEN on rate limit errors ([de13a55](https://github.com/koki-develop/ghasec/commit/de13a5531304152dfe63c4865d1f2836b7a2a832))

## [0.1.0](https://github.com/koki-develop/ghasec/compare/v0.0.5...v0.1.0) (2026-03-24)


### Features

* add --format flag with github-actions output format ([cfbc74a](https://github.com/koki-develop/ghasec/commit/cfbc74a746174f86c89cb762453f321259bc3ed2))
* add impostor-commit rule ([aaeb73b](https://github.com/koki-develop/ghasec/commit/aaeb73b91c032194788c620b673c9c4d0e6f22af))

## [0.0.5](https://github.com/koki-develop/ghasec/compare/v0.0.4...v0.0.5) (2026-03-24)


### Features

* add Dockerfile for running ghasec via pre-built binary ([3ef3422](https://github.com/koki-develop/ghasec/commit/3ef34226b64286ace30eb9762a8a743542aedf4f))
* add missing-sha-ref-comment rule ([1a47775](https://github.com/koki-develop/ghasec/commit/1a477757246efa386be5d2c135e5a12fb7de9e28))
* Release v0.0.5 ([535b199](https://github.com/koki-develop/ghasec/commit/535b199a32c8054fb9ee88930a82b98e741b71b0))


### Patches

* pass GHASEC_VERSION build arg to Docker build-push-action ([c72737b](https://github.com/koki-develop/ghasec/commit/c72737bede23f7bad59ac9ac78f26561455db1ac))
* remove example hint from missing-ref diagnostic message ([d11121f](https://github.com/koki-develop/ghasec/commit/d11121f13dd267df90ed2d19dac5bf1ad2565230))
* remove misleading hint from default-permissions missing message ([b38c4cd](https://github.com/koki-develop/ghasec/commit/b38c4cda0ea8198fabcc59d12fe9348825174f2d))

## [0.0.4](https://github.com/koki-develop/ghasec/compare/v0.0.3...v0.0.4) (2026-03-24)


### Patches

* remove unnecessary local tag creation before goreleaser ([ba5b545](https://github.com/koki-develop/ghasec/commit/ba5b54523f14e00cae5d873a4c79561cdb1cac17))

## [0.0.3](https://github.com/koki-develop/ghasec/compare/v0.1.0...v0.0.3) (2026-03-24)


### Features

* add --no-color flag to disable colored output ([108cf7b](https://github.com/koki-develop/ghasec/commit/108cf7b82ec59b3f8eed9bc84df01d6077cdabcf))
* add --version flag with ldflags and build info support ([3419ea0](https://github.com/koki-develop/ghasec/commit/3419ea039360af6510647f3574011a0431dc50cd))
* add action.yml/action.yaml linting support with invalid-action rule ([332d166](https://github.com/koki-develop/ghasec/commit/332d1667fef923496e5d540ac876501556324b3c))
* add AfterToken for showing context lines after error ([a14135a](https://github.com/koki-develop/ghasec/commit/a14135ac2908eb152cbaabe150d42aea51f2bc00))
* add arrow prefix and rule reference URL to error output ([3d22513](https://github.com/koki-develop/ghasec/commit/3d22513e20c1d8343ab20a36f9702bec4d2bb8a2))
* add checkout-persist-credentials rule ([7aedcb4](https://github.com/koki-develop/ghasec/commit/7aedcb48cfc1db93b12953205bd9bc15cb6610cc))
* add cobra CLI skeleton with root command and main entrypoint ([a27209e](https://github.com/koki-develop/ghasec/commit/a27209ea55c0142125814895c6e743ff5a2b4e86))
* add default-permissions rule ([628f115](https://github.com/koki-develop/ghasec/commit/628f115d733246bcb2f9ef728c89d437eceb7f5b))
* add E2E testing framework with NO_COLOR support ([4d1c01e](https://github.com/koki-develop/ghasec/commit/4d1c01e1847d7cd65a2ef2009ecbbdb5ba4b9e1e))
* add expression syntax validation and forbid expressions in static positions ([307eaf6](https://github.com/koki-develop/ghasec/commit/307eaf614c8c44a4bd4e77c61c3527932eac047c))
* add ghasec-ignore comment directive for suppressing diagnostics ([213f154](https://github.com/koki-develop/ghasec/commit/213f1548461fc4e6eaa0e92f8d9b49d929c51abe))
* add Homebrew formula generator command ([b57f516](https://github.com/koki-develop/ghasec/commit/b57f516a9c888da1eaaa6cf50e5b09fe4a90b91a))
* add job-all-permissions rule to prohibit read-all/write-all at job level ([77d5dfe](https://github.com/koki-develop/ghasec/commit/77d5dfec61664bdbe3a2071bce9ce69345865b79))
* add job-timeout-minutes rule and make invalid-workflow key validation type-aware ([d66fd32](https://github.com/koki-develop/ghasec/commit/d66fd32fa269ecc825eccf7a2d870bb2fc786175))
* add mismatched-sha-tag rule ([a9b1736](https://github.com/koki-develop/ghasec/commit/a9b1736fa7e1757b6201d24a2ec5e31d8613f612))
* add schema-inexpressible validations for step ID uniqueness, needs validity, dependency checks, event types, cron syntax, choice defaults, and filter negation ([b61171c](https://github.com/koki-develop/ghasec/commit/b61171cb7b187b7034a15b45c79bbf05eb4e9cb8))
* add script-injection rule and fix multiline expression positioning ([6a64e0f](https://github.com/koki-develop/ghasec/commit/6a64e0fb8ec41aba38b9632bcfe253d21c87216a))
* add secondary markers to diagnostics for uses+steps conflict ([3acf482](https://github.com/koki-develop/ghasec/commit/3acf482967503a864c16ec1b97295d0d6e2fd5a1))
* add secondary markers to runs-on+uses conflict diagnostic ([8818439](https://github.com/koki-develop/ghasec/commit/88184398c22a4d0e352455412dc4b1eff70a99ef))
* add sequence entry token as breadcrumb context for step-level diagnostics ([87efbac](https://github.com/koki-develop/ghasec/commit/87efbac5adb923bee4e0c732f033a536bba0ee90))
* add step action SHA pinning validation rule ([57806e1](https://github.com/koki-develop/ghasec/commit/57806e177e56eb31339b64c9b789e5efb2d53f8c))
* add workflow validation with required field and type checks ([26c41d8](https://github.com/koki-develop/ghasec/commit/26c41d856d077b8c7b4800d246904cfa93629cf7))
* add workflow YAML loading with file discovery, parsing, and error display ([6ce2514](https://github.com/koki-develop/ghasec/commit/6ce2514ad7aff39b5b666e114f599dd6de5b35ed))
* add YAML syntax highlighting to diagnostic output ([64e7f14](https://github.com/koki-develop/ghasec/commit/64e7f14e3717abd2ecd8cb736c98ac997e413084))
* bold filenames in error output and return errors from fallback paths ([c5a8298](https://github.com/koki-develop/ghasec/commit/c5a8298aa410b00de5afdeeb1b790fed65b32b2d))
* emit required-field diagnostics before unknown-key diagnostics at same position ([da59ac2](https://github.com/koki-develop/ghasec/commit/da59ac27b17228dbdf9434189a4bae0899e32d16))
* generate structural validation from JSON Schema via SchemaStore submodule ([72bc6d6](https://github.com/koki-develop/ghasec/commit/72bc6d68e74265d97260bff0c90a1f13cdd5c613))
* improve diagnostic label positioning for job errors and unpinned refs ([0ce65be](https://github.com/koki-develop/ghasec/commit/0ce65be469fe07988c04870441bb81927a23b66b))
* include line and column numbers in error file path ([914acd2](https://github.com/koki-develop/ghasec/commit/914acd270c77bce000b8abb6883812f9549e777e))
* include rule ID in diagnostic error output ([3e71b22](https://github.com/koki-develop/ghasec/commit/3e71b2258cbf74e179015328c980033d50f39d79))
* make online rules opt-in via --online flag ([5266e95](https://github.com/koki-develop/ghasec/commit/5266e95fab58ea1a51b1d009304dc485a450a2ee))
* parallelize file-level and rule-level execution with deterministic output ordering ([d4d3d71](https://github.com/koki-develop/ghasec/commit/d4d3d712b07e64501b45e030c5733bb79d126931))
* Release v0.0.1 ([45fe697](https://github.com/koki-develop/ghasec/commit/45fe69766dd15d4bf8f4337858cb2ecad658d2d3))
* Release v0.0.2 ([4094627](https://github.com/koki-develop/ghasec/commit/409462728ee775c1f137fd878194092c204755a4))
* Release v0.0.3 ([9b2fa62](https://github.com/koki-develop/ghasec/commit/9b2fa6253561708716b191a6f79af6ba67df1046))
* replace cobra error output with error count summary ([93301ca](https://github.com/koki-develop/ghasec/commit/93301ca8351000ba01f8eec5b5496ca46961f499))
* replace hand-written structural validation with JSON Schema generated code ([fea6936](https://github.com/koki-develop/ghasec/commit/fea693632f54635547e6938dd958cc71eacfd8e1))
* require @&lt;ref&gt; on remote actions in invalid-workflow rule ([41d0f99](https://github.com/koki-develop/ghasec/commit/41d0f9962004696a3223b87a85ccb45ba267ff2f))
* show context lines before error using ContextToken ([19159b9](https://github.com/koki-develop/ghasec/commit/19159b99f28241f358be8c76f758eab652de8e82))
* sort diagnostics by position (line, column) instead of rule registration order ([3b409ad](https://github.com/koki-develop/ghasec/commit/3b409adfdbb4398e96b73ede52ffe698ece8c386))
* strengthen invalid-workflow rule with comprehensive structural validation ([243d846](https://github.com/koki-develop/ghasec/commit/243d846c4b0957ebf88260aba58cce22571ab665))
* support subdirectory test cases in E2E framework ([46f3ad7](https://github.com/koki-develop/ghasec/commit/46f3ad7b0baf14c2c8b6a29b60b95571095605c6))
* validate runs-on mapping keys and sequence element types ([7ef2f1e](https://github.com/koki-develop/ghasec/commit/7ef2f1ee8864d073b1a0bd4779f9c697ca1c0d66))


### Patches

* add BeforeToken to invalid-workflow errors for key context display ([9705bad](https://github.com/koki-develop/ghasec/commit/9705bad2e2c43c7eb6921559f3e3485e02b716c5))
* add jobs key breadcrumb to all invalid-workflow job-level errors ([65857b8](https://github.com/koki-develop/ghasec/commit/65857b88854269c2381642adc83730ca46bb8faa))
* allow expressions in action.yml inputs.*.default ([b89fde3](https://github.com/koki-develop/ghasec/commit/b89fde3737d6527c487a26c6d2b270a5c21af8a7))
* annotate missing required fields at file start instead of first mapping key ([e5607cb](https://github.com/koki-develop/ghasec/commit/e5607cbadf398685c5fc0ff1e790cd991e708f2d))
* apply italic style to Ref: label in diagnostic output ([c356c9f](https://github.com/koki-develop/ghasec/commit/c356c9f38ecc3cc496739f0fab31d931fa6238c2))
* correct annotation span offset for goccy/go-yaml 1-indexed tokens ([8cb119d](https://github.com/koki-develop/ghasec/commit/8cb119db19814fa12761dd33c697fbb04abf9095))
* correct diagnostic label positions for quoted YAML string values ([7d5fde9](https://github.com/koki-develop/ghasec/commit/7d5fde9f0f551e8a583f4223586617317c393990))
* create local tag before goreleaser to support draft releases ([12d1db3](https://github.com/koki-develop/ghasec/commit/12d1db3ad21fd13d7a0f5d54c1b2df373eb0385b))
* handle errcheck warnings for os.RemoveAll in E2E tests ([a284539](https://github.com/koki-develop/ghasec/commit/a2845391c1719ce7ce4b117457c9227125c60eec))
* point diagnostic caret at tag text instead of comment token ([9eb7830](https://github.com/koki-develop/ghasec/commit/9eb78303af2e07058b912f5a8faf8f7f0594a790))
* reject directory arguments with clear error message ([5d1cf73](https://github.com/koki-develop/ghasec/commit/5d1cf7373f2006482254cc9e72acbe897c68c621))
* report missing required fields for empty workflow files ([f687b6d](https://github.com/koki-develop/ghasec/commit/f687b6df205199ea188a8f7da57894e158fcd030))
* resolve alias false positives, enable event body validation, detect invalid job IDs, and add minItems to oneOf ([175283a](https://github.com/koki-develop/ghasec/commit/175283a3bd358a27e7226c98948c9bd4a6e2313e))
* show all permission entries in default-permissions diagnostic context ([9e96d91](https://github.com/koki-develop/ghasec/commit/9e96d91f65dcdbfad2af299f9e670ca8f0cadff4))
* stop requiring documentation-only fields in action.yml validation ([5eb2e01](https://github.com/koki-develop/ghasec/commit/5eb2e0196528397864f59e6a061fea9a518b2a9f))
* truncate annotation span at newline to prevent cross-line labels ([9e88310](https://github.com/koki-develop/ghasec/commit/9e88310db3ee758e14a21e546e5b01d994c4d7b4))
* unwrap anchor nodes in rules and fix bare if block scalar marker positioning ([aa8c8f4](https://github.com/koki-develop/ghasec/commit/aa8c8f41de32668edc246589b19e1e3c09a683a9))

## [0.1.0](https://github.com/koki-develop/ghasec/compare/v0.0.2...v0.1.0) (2026-03-24)


### Features

* add Homebrew formula generator command ([b57f516](https://github.com/koki-develop/ghasec/commit/b57f516a9c888da1eaaa6cf50e5b09fe4a90b91a))
* add script-injection rule and fix multiline expression positioning ([6a64e0f](https://github.com/koki-develop/ghasec/commit/6a64e0fb8ec41aba38b9632bcfe253d21c87216a))


### Patches

* apply italic style to Ref: label in diagnostic output ([c356c9f](https://github.com/koki-develop/ghasec/commit/c356c9f38ecc3cc496739f0fab31d931fa6238c2))
* unwrap anchor nodes in rules and fix bare if block scalar marker positioning ([aa8c8f4](https://github.com/koki-develop/ghasec/commit/aa8c8f41de32668edc246589b19e1e3c09a683a9))

## [0.0.2](https://github.com/koki-develop/ghasec/compare/v0.0.1...v0.0.2) (2026-03-24)


### Features

* Release v0.0.2 ([4094627](https://github.com/koki-develop/ghasec/commit/409462728ee775c1f137fd878194092c204755a4))

## [0.0.1](https://github.com/koki-develop/ghasec/compare/v0.0.1...v0.0.1) (2026-03-24)


### Features

* add --no-color flag to disable colored output ([108cf7b](https://github.com/koki-develop/ghasec/commit/108cf7b82ec59b3f8eed9bc84df01d6077cdabcf))
* add --version flag with ldflags and build info support ([3419ea0](https://github.com/koki-develop/ghasec/commit/3419ea039360af6510647f3574011a0431dc50cd))
* add action.yml/action.yaml linting support with invalid-action rule ([332d166](https://github.com/koki-develop/ghasec/commit/332d1667fef923496e5d540ac876501556324b3c))
* add AfterToken for showing context lines after error ([a14135a](https://github.com/koki-develop/ghasec/commit/a14135ac2908eb152cbaabe150d42aea51f2bc00))
* add arrow prefix and rule reference URL to error output ([3d22513](https://github.com/koki-develop/ghasec/commit/3d22513e20c1d8343ab20a36f9702bec4d2bb8a2))
* add checkout-persist-credentials rule ([7aedcb4](https://github.com/koki-develop/ghasec/commit/7aedcb48cfc1db93b12953205bd9bc15cb6610cc))
* add cobra CLI skeleton with root command and main entrypoint ([a27209e](https://github.com/koki-develop/ghasec/commit/a27209ea55c0142125814895c6e743ff5a2b4e86))
* add default-permissions rule ([628f115](https://github.com/koki-develop/ghasec/commit/628f115d733246bcb2f9ef728c89d437eceb7f5b))
* add E2E testing framework with NO_COLOR support ([4d1c01e](https://github.com/koki-develop/ghasec/commit/4d1c01e1847d7cd65a2ef2009ecbbdb5ba4b9e1e))
* add expression syntax validation and forbid expressions in static positions ([307eaf6](https://github.com/koki-develop/ghasec/commit/307eaf614c8c44a4bd4e77c61c3527932eac047c))
* add ghasec-ignore comment directive for suppressing diagnostics ([213f154](https://github.com/koki-develop/ghasec/commit/213f1548461fc4e6eaa0e92f8d9b49d929c51abe))
* add job-all-permissions rule to prohibit read-all/write-all at job level ([77d5dfe](https://github.com/koki-develop/ghasec/commit/77d5dfec61664bdbe3a2071bce9ce69345865b79))
* add job-timeout-minutes rule and make invalid-workflow key validation type-aware ([d66fd32](https://github.com/koki-develop/ghasec/commit/d66fd32fa269ecc825eccf7a2d870bb2fc786175))
* add mismatched-sha-tag rule ([a9b1736](https://github.com/koki-develop/ghasec/commit/a9b1736fa7e1757b6201d24a2ec5e31d8613f612))
* add schema-inexpressible validations for step ID uniqueness, needs validity, dependency checks, event types, cron syntax, choice defaults, and filter negation ([b61171c](https://github.com/koki-develop/ghasec/commit/b61171cb7b187b7034a15b45c79bbf05eb4e9cb8))
* add secondary markers to diagnostics for uses+steps conflict ([3acf482](https://github.com/koki-develop/ghasec/commit/3acf482967503a864c16ec1b97295d0d6e2fd5a1))
* add secondary markers to runs-on+uses conflict diagnostic ([8818439](https://github.com/koki-develop/ghasec/commit/88184398c22a4d0e352455412dc4b1eff70a99ef))
* add sequence entry token as breadcrumb context for step-level diagnostics ([87efbac](https://github.com/koki-develop/ghasec/commit/87efbac5adb923bee4e0c732f033a536bba0ee90))
* add step action SHA pinning validation rule ([57806e1](https://github.com/koki-develop/ghasec/commit/57806e177e56eb31339b64c9b789e5efb2d53f8c))
* add workflow validation with required field and type checks ([26c41d8](https://github.com/koki-develop/ghasec/commit/26c41d856d077b8c7b4800d246904cfa93629cf7))
* add workflow YAML loading with file discovery, parsing, and error display ([6ce2514](https://github.com/koki-develop/ghasec/commit/6ce2514ad7aff39b5b666e114f599dd6de5b35ed))
* add YAML syntax highlighting to diagnostic output ([64e7f14](https://github.com/koki-develop/ghasec/commit/64e7f14e3717abd2ecd8cb736c98ac997e413084))
* bold filenames in error output and return errors from fallback paths ([c5a8298](https://github.com/koki-develop/ghasec/commit/c5a8298aa410b00de5afdeeb1b790fed65b32b2d))
* emit required-field diagnostics before unknown-key diagnostics at same position ([da59ac2](https://github.com/koki-develop/ghasec/commit/da59ac27b17228dbdf9434189a4bae0899e32d16))
* generate structural validation from JSON Schema via SchemaStore submodule ([72bc6d6](https://github.com/koki-develop/ghasec/commit/72bc6d68e74265d97260bff0c90a1f13cdd5c613))
* improve diagnostic label positioning for job errors and unpinned refs ([0ce65be](https://github.com/koki-develop/ghasec/commit/0ce65be469fe07988c04870441bb81927a23b66b))
* include line and column numbers in error file path ([914acd2](https://github.com/koki-develop/ghasec/commit/914acd270c77bce000b8abb6883812f9549e777e))
* include rule ID in diagnostic error output ([3e71b22](https://github.com/koki-develop/ghasec/commit/3e71b2258cbf74e179015328c980033d50f39d79))
* make online rules opt-in via --online flag ([5266e95](https://github.com/koki-develop/ghasec/commit/5266e95fab58ea1a51b1d009304dc485a450a2ee))
* parallelize file-level and rule-level execution with deterministic output ordering ([d4d3d71](https://github.com/koki-develop/ghasec/commit/d4d3d712b07e64501b45e030c5733bb79d126931))
* Release v0.0.1 ([45fe697](https://github.com/koki-develop/ghasec/commit/45fe69766dd15d4bf8f4337858cb2ecad658d2d3))
* replace cobra error output with error count summary ([93301ca](https://github.com/koki-develop/ghasec/commit/93301ca8351000ba01f8eec5b5496ca46961f499))
* replace hand-written structural validation with JSON Schema generated code ([fea6936](https://github.com/koki-develop/ghasec/commit/fea693632f54635547e6938dd958cc71eacfd8e1))
* require @&lt;ref&gt; on remote actions in invalid-workflow rule ([41d0f99](https://github.com/koki-develop/ghasec/commit/41d0f9962004696a3223b87a85ccb45ba267ff2f))
* show context lines before error using ContextToken ([19159b9](https://github.com/koki-develop/ghasec/commit/19159b99f28241f358be8c76f758eab652de8e82))
* sort diagnostics by position (line, column) instead of rule registration order ([3b409ad](https://github.com/koki-develop/ghasec/commit/3b409adfdbb4398e96b73ede52ffe698ece8c386))
* strengthen invalid-workflow rule with comprehensive structural validation ([243d846](https://github.com/koki-develop/ghasec/commit/243d846c4b0957ebf88260aba58cce22571ab665))
* support subdirectory test cases in E2E framework ([46f3ad7](https://github.com/koki-develop/ghasec/commit/46f3ad7b0baf14c2c8b6a29b60b95571095605c6))
* validate runs-on mapping keys and sequence element types ([7ef2f1e](https://github.com/koki-develop/ghasec/commit/7ef2f1ee8864d073b1a0bd4779f9c697ca1c0d66))


### Patches

* add BeforeToken to invalid-workflow errors for key context display ([9705bad](https://github.com/koki-develop/ghasec/commit/9705bad2e2c43c7eb6921559f3e3485e02b716c5))
* add jobs key breadcrumb to all invalid-workflow job-level errors ([65857b8](https://github.com/koki-develop/ghasec/commit/65857b88854269c2381642adc83730ca46bb8faa))
* allow expressions in action.yml inputs.*.default ([b89fde3](https://github.com/koki-develop/ghasec/commit/b89fde3737d6527c487a26c6d2b270a5c21af8a7))
* annotate missing required fields at file start instead of first mapping key ([e5607cb](https://github.com/koki-develop/ghasec/commit/e5607cbadf398685c5fc0ff1e790cd991e708f2d))
* correct annotation span offset for goccy/go-yaml 1-indexed tokens ([8cb119d](https://github.com/koki-develop/ghasec/commit/8cb119db19814fa12761dd33c697fbb04abf9095))
* correct diagnostic label positions for quoted YAML string values ([7d5fde9](https://github.com/koki-develop/ghasec/commit/7d5fde9f0f551e8a583f4223586617317c393990))
* create local tag before goreleaser to support draft releases ([12d1db3](https://github.com/koki-develop/ghasec/commit/12d1db3ad21fd13d7a0f5d54c1b2df373eb0385b))
* handle errcheck warnings for os.RemoveAll in E2E tests ([a284539](https://github.com/koki-develop/ghasec/commit/a2845391c1719ce7ce4b117457c9227125c60eec))
* point diagnostic caret at tag text instead of comment token ([9eb7830](https://github.com/koki-develop/ghasec/commit/9eb78303af2e07058b912f5a8faf8f7f0594a790))
* reject directory arguments with clear error message ([5d1cf73](https://github.com/koki-develop/ghasec/commit/5d1cf7373f2006482254cc9e72acbe897c68c621))
* report missing required fields for empty workflow files ([f687b6d](https://github.com/koki-develop/ghasec/commit/f687b6df205199ea188a8f7da57894e158fcd030))
* resolve alias false positives, enable event body validation, detect invalid job IDs, and add minItems to oneOf ([175283a](https://github.com/koki-develop/ghasec/commit/175283a3bd358a27e7226c98948c9bd4a6e2313e))
* show all permission entries in default-permissions diagnostic context ([9e96d91](https://github.com/koki-develop/ghasec/commit/9e96d91f65dcdbfad2af299f9e670ca8f0cadff4))
* stop requiring documentation-only fields in action.yml validation ([5eb2e01](https://github.com/koki-develop/ghasec/commit/5eb2e0196528397864f59e6a061fea9a518b2a9f))
* truncate annotation span at newline to prevent cross-line labels ([9e88310](https://github.com/koki-develop/ghasec/commit/9e88310db3ee758e14a21e546e5b01d994c4d7b4))

## 0.0.1 (2026-03-24)


### Features

* add --no-color flag to disable colored output ([108cf7b](https://github.com/koki-develop/ghasec/commit/108cf7b82ec59b3f8eed9bc84df01d6077cdabcf))
* add --version flag with ldflags and build info support ([3419ea0](https://github.com/koki-develop/ghasec/commit/3419ea039360af6510647f3574011a0431dc50cd))
* add action.yml/action.yaml linting support with invalid-action rule ([332d166](https://github.com/koki-develop/ghasec/commit/332d1667fef923496e5d540ac876501556324b3c))
* add AfterToken for showing context lines after error ([a14135a](https://github.com/koki-develop/ghasec/commit/a14135ac2908eb152cbaabe150d42aea51f2bc00))
* add arrow prefix and rule reference URL to error output ([3d22513](https://github.com/koki-develop/ghasec/commit/3d22513e20c1d8343ab20a36f9702bec4d2bb8a2))
* add checkout-persist-credentials rule ([7aedcb4](https://github.com/koki-develop/ghasec/commit/7aedcb48cfc1db93b12953205bd9bc15cb6610cc))
* add cobra CLI skeleton with root command and main entrypoint ([a27209e](https://github.com/koki-develop/ghasec/commit/a27209ea55c0142125814895c6e743ff5a2b4e86))
* add default-permissions rule ([628f115](https://github.com/koki-develop/ghasec/commit/628f115d733246bcb2f9ef728c89d437eceb7f5b))
* add E2E testing framework with NO_COLOR support ([4d1c01e](https://github.com/koki-develop/ghasec/commit/4d1c01e1847d7cd65a2ef2009ecbbdb5ba4b9e1e))
* add expression syntax validation and forbid expressions in static positions ([307eaf6](https://github.com/koki-develop/ghasec/commit/307eaf614c8c44a4bd4e77c61c3527932eac047c))
* add ghasec-ignore comment directive for suppressing diagnostics ([213f154](https://github.com/koki-develop/ghasec/commit/213f1548461fc4e6eaa0e92f8d9b49d929c51abe))
* add job-all-permissions rule to prohibit read-all/write-all at job level ([77d5dfe](https://github.com/koki-develop/ghasec/commit/77d5dfec61664bdbe3a2071bce9ce69345865b79))
* add job-timeout-minutes rule and make invalid-workflow key validation type-aware ([d66fd32](https://github.com/koki-develop/ghasec/commit/d66fd32fa269ecc825eccf7a2d870bb2fc786175))
* add mismatched-sha-tag rule ([a9b1736](https://github.com/koki-develop/ghasec/commit/a9b1736fa7e1757b6201d24a2ec5e31d8613f612))
* add schema-inexpressible validations for step ID uniqueness, needs validity, dependency checks, event types, cron syntax, choice defaults, and filter negation ([b61171c](https://github.com/koki-develop/ghasec/commit/b61171cb7b187b7034a15b45c79bbf05eb4e9cb8))
* add secondary markers to diagnostics for uses+steps conflict ([3acf482](https://github.com/koki-develop/ghasec/commit/3acf482967503a864c16ec1b97295d0d6e2fd5a1))
* add secondary markers to runs-on+uses conflict diagnostic ([8818439](https://github.com/koki-develop/ghasec/commit/88184398c22a4d0e352455412dc4b1eff70a99ef))
* add sequence entry token as breadcrumb context for step-level diagnostics ([87efbac](https://github.com/koki-develop/ghasec/commit/87efbac5adb923bee4e0c732f033a536bba0ee90))
* add step action SHA pinning validation rule ([57806e1](https://github.com/koki-develop/ghasec/commit/57806e177e56eb31339b64c9b789e5efb2d53f8c))
* add workflow validation with required field and type checks ([26c41d8](https://github.com/koki-develop/ghasec/commit/26c41d856d077b8c7b4800d246904cfa93629cf7))
* add workflow YAML loading with file discovery, parsing, and error display ([6ce2514](https://github.com/koki-develop/ghasec/commit/6ce2514ad7aff39b5b666e114f599dd6de5b35ed))
* add YAML syntax highlighting to diagnostic output ([64e7f14](https://github.com/koki-develop/ghasec/commit/64e7f14e3717abd2ecd8cb736c98ac997e413084))
* bold filenames in error output and return errors from fallback paths ([c5a8298](https://github.com/koki-develop/ghasec/commit/c5a8298aa410b00de5afdeeb1b790fed65b32b2d))
* emit required-field diagnostics before unknown-key diagnostics at same position ([da59ac2](https://github.com/koki-develop/ghasec/commit/da59ac27b17228dbdf9434189a4bae0899e32d16))
* generate structural validation from JSON Schema via SchemaStore submodule ([72bc6d6](https://github.com/koki-develop/ghasec/commit/72bc6d68e74265d97260bff0c90a1f13cdd5c613))
* improve diagnostic label positioning for job errors and unpinned refs ([0ce65be](https://github.com/koki-develop/ghasec/commit/0ce65be469fe07988c04870441bb81927a23b66b))
* include line and column numbers in error file path ([914acd2](https://github.com/koki-develop/ghasec/commit/914acd270c77bce000b8abb6883812f9549e777e))
* include rule ID in diagnostic error output ([3e71b22](https://github.com/koki-develop/ghasec/commit/3e71b2258cbf74e179015328c980033d50f39d79))
* make online rules opt-in via --online flag ([5266e95](https://github.com/koki-develop/ghasec/commit/5266e95fab58ea1a51b1d009304dc485a450a2ee))
* parallelize file-level and rule-level execution with deterministic output ordering ([d4d3d71](https://github.com/koki-develop/ghasec/commit/d4d3d712b07e64501b45e030c5733bb79d126931))
* Release v0.0.1 ([45fe697](https://github.com/koki-develop/ghasec/commit/45fe69766dd15d4bf8f4337858cb2ecad658d2d3))
* replace cobra error output with error count summary ([93301ca](https://github.com/koki-develop/ghasec/commit/93301ca8351000ba01f8eec5b5496ca46961f499))
* replace hand-written structural validation with JSON Schema generated code ([fea6936](https://github.com/koki-develop/ghasec/commit/fea693632f54635547e6938dd958cc71eacfd8e1))
* require @&lt;ref&gt; on remote actions in invalid-workflow rule ([41d0f99](https://github.com/koki-develop/ghasec/commit/41d0f9962004696a3223b87a85ccb45ba267ff2f))
* show context lines before error using ContextToken ([19159b9](https://github.com/koki-develop/ghasec/commit/19159b99f28241f358be8c76f758eab652de8e82))
* sort diagnostics by position (line, column) instead of rule registration order ([3b409ad](https://github.com/koki-develop/ghasec/commit/3b409adfdbb4398e96b73ede52ffe698ece8c386))
* strengthen invalid-workflow rule with comprehensive structural validation ([243d846](https://github.com/koki-develop/ghasec/commit/243d846c4b0957ebf88260aba58cce22571ab665))
* support subdirectory test cases in E2E framework ([46f3ad7](https://github.com/koki-develop/ghasec/commit/46f3ad7b0baf14c2c8b6a29b60b95571095605c6))
* validate runs-on mapping keys and sequence element types ([7ef2f1e](https://github.com/koki-develop/ghasec/commit/7ef2f1ee8864d073b1a0bd4779f9c697ca1c0d66))


### Patches

* add BeforeToken to invalid-workflow errors for key context display ([9705bad](https://github.com/koki-develop/ghasec/commit/9705bad2e2c43c7eb6921559f3e3485e02b716c5))
* add jobs key breadcrumb to all invalid-workflow job-level errors ([65857b8](https://github.com/koki-develop/ghasec/commit/65857b88854269c2381642adc83730ca46bb8faa))
* annotate missing required fields at file start instead of first mapping key ([e5607cb](https://github.com/koki-develop/ghasec/commit/e5607cbadf398685c5fc0ff1e790cd991e708f2d))
* correct annotation span offset for goccy/go-yaml 1-indexed tokens ([8cb119d](https://github.com/koki-develop/ghasec/commit/8cb119db19814fa12761dd33c697fbb04abf9095))
* correct diagnostic label positions for quoted YAML string values ([7d5fde9](https://github.com/koki-develop/ghasec/commit/7d5fde9f0f551e8a583f4223586617317c393990))
* handle errcheck warnings for os.RemoveAll in E2E tests ([a284539](https://github.com/koki-develop/ghasec/commit/a2845391c1719ce7ce4b117457c9227125c60eec))
* point diagnostic caret at tag text instead of comment token ([9eb7830](https://github.com/koki-develop/ghasec/commit/9eb78303af2e07058b912f5a8faf8f7f0594a790))
* reject directory arguments with clear error message ([5d1cf73](https://github.com/koki-develop/ghasec/commit/5d1cf7373f2006482254cc9e72acbe897c68c621))
* report missing required fields for empty workflow files ([f687b6d](https://github.com/koki-develop/ghasec/commit/f687b6df205199ea188a8f7da57894e158fcd030))
* resolve alias false positives, enable event body validation, detect invalid job IDs, and add minItems to oneOf ([175283a](https://github.com/koki-develop/ghasec/commit/175283a3bd358a27e7226c98948c9bd4a6e2313e))
* show all permission entries in default-permissions diagnostic context ([9e96d91](https://github.com/koki-develop/ghasec/commit/9e96d91f65dcdbfad2af299f9e670ca8f0cadff4))
* stop requiring documentation-only fields in action.yml validation ([5eb2e01](https://github.com/koki-develop/ghasec/commit/5eb2e0196528397864f59e6a061fea9a518b2a9f))
* truncate annotation span at newline to prevent cross-line labels ([9e88310](https://github.com/koki-develop/ghasec/commit/9e88310db3ee758e14a21e546e5b01d994c4d7b4))
