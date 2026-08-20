# Kilix content contracts

These Draft 2020-12 JSON Schemas are the frozen F100 v1 contracts for 0.2.1.
The cross-consumer review and complete structural/semantic fixture matrix
passed on 2026-08-19. They are language-neutral and are also enforced by the
schema-v4 catalog parser.

- `kilix.content.asset-v1.schema.json` describes immutable, non-executable
  assets. Exactly one source mode is allowed: mirrored or user-supplied.
- `kilix.install.license-v1.schema.json` describes UI-originated decisions and
  retained receipts. A restricted decision can only decline and can never
  become a receipt.

Portable JSON Schema cannot express several cross-field rules. They are still
normative v1 requirements and every implementation must enforce them:

- asset manifest paths are unique;
- `sizes.installed_bytes` equals the sum of manifest file sizes;
- `compatibility.minimum` is not greater than `maximum`;
- conversion argv contains `{input}` and `{output}` exactly once each, as
  separate argv elements; no other element contains a brace, and substitution
  never invokes a shell; and
- a user-supplied source links at least one `user-supplied` license decision.

The fixture suite executes these rules independently of structural schema
validation. Future non-Python readers must pass the same golden fixtures.
Frozen schema SHA-256 values:

- `kilix.content.asset/v1`: `89d4865d11d6a537328965a8a903ac07d7dcf0ea14e1b360888f22af7ba5a1a8`
- `kilix.install.license/v1`: `2f352856b4bd712e6030b2c74a690f7c0ed250e5730a69aa04b601643dbf1736`

Built wheels install the schemas below `share/kilix-content/contracts`; source
archives retain this complete `contracts/` directory.

`tests/fixtures/contracts/valid` contains canonical accepted instances;
`invalid` contains one rejected condition per file. `SHA256SUMS` pins every
schema and fixture byte. After this freeze, any semantic contract change
requires a new schema version rather than silently changing these files.

Fixture names begin with the schema they exercise (`asset-` or `license-`).
Every JSON file is UTF-8, uses two-space indentation and sorted object keys,
and ends with one newline. Regenerate the manifest only after reviewing the
semantic diff:

```sh
python tests/update_contract_hashes.py
```

Run the contract gate from the repository root with:

```sh
uv sync --locked --group test --no-install-project
uv run --locked --no-sync \
  python -m unittest discover -s tests -p 'test_contracts.py' -v
```

The validator enables JSON Schema format checking, so malformed HTTPS URIs and
timestamps fail rather than being treated as annotations. A valid fixture must
pass exactly its named schema. Each invalid fixture pins its expected failing
instance path and validator keyword so rejection for an unrelated reason does
not conceal a schema regression.
