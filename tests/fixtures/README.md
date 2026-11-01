# Conformance fixtures

Copied from the ZevAuth server-SDK contract,
<https://github.com/zevop/zevauth-sdk/tree/main/spec>. Every ZevAuth server
library (Node, PHP, Python, Ruby, Go, Java) runs these same files, which is
what keeps them behaving identically.

Don't edit these copies. Change the contract and regenerate there, then run
`composer sync-fixtures`.

The keys in `keys/` are test-only. They are valid nowhere else.
