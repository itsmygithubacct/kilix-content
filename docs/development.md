# Development

## Test

```sh
make test
make benchmark
```

Tests use local Git repositories and in-memory archives. They cover catalog
validation, shared-package installation/readiness, fragmented installation
failures, recursive dependency checkout, dirty/wrong-origin refusal, atomic
replacement, traversal and symlink rejection, checksum enforcement, bounded
child diagnostics, and executable readiness. The benchmark records cached and
cold catalog cost, indexed lookup, managed Git verification/readiness, and a
verified 32 MiB download.
