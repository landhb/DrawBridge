# Parsing Harness

Install AFL:

```sh
cargo install afl
```

Build the target:

```sh
cargo afl build
```

Then run the fuzzer:

```sh
cargo afl fuzz -i in -o out target/debug/parser-fuzz-target
```

Any crash files can be fed back in with:

```sh
cargo test 
```