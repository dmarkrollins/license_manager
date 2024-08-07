### Get Started

Install handy key file generation utility.

```go install github.com/hyperboloide/lk/lkgen@latest```

### Generate Key Files

```lkgen gen --output=./private.key```

```lkgen pub ./private.key --output=./public.key```

Example should now work.

```go run main.go```

