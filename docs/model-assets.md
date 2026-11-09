# Model assets, licence gating and receipts

Model assets are the `assets` array of the packaged catalog: asset/v3 records
whose files are fetched from upstream on first use, after the licence screen,
and verified against the record before they are selected. The licence records,
the screen, agreement capture and receipt storage belong to
[kilix-license](https://github.com/itsmygithubacct/kilix-license#readme), which
this repository vendors under `third_party/kilix-license`.

## Installing a model asset from bytes you already hold

The `lfm2-kilix-commands` asset is a Kilix-trained derivative of the pinned
Liquid AI model. Its archive is published by `kilix-needle`, with the LFM Open
License v1.0, runtime licences and a modification notice. The catalog permits
its named, versioned release archive under this owned-model route. The optional
`needle3-kilix-commands` asset similarly packages the Kilix-trained Needle 3 V9
epoch-1 model, its cached CPU runtime, original Apache-2.0 and MIT licences,
modification notices and runtime source. It is installed through
`kilix-needle install --commands needle3`; LFM2 remains the Ask default.
Other model assets retain their upstream-only source requirement. First-use
consent and archive/member checksums apply to both derivatives.

An asset can opt into `"storage": "versioned"` to keep each installed manifest
in its own directory. Use `Installer.asset_destination(spec)` to resolve that
directory. Upgrades preserve earlier bytes and receipts, and restoring an
earlier catalog selects its earlier installation. A changed manifest still
requires its own covering receipt; failed installs leave earlier versions intact.

Model assets are normally fetched from upstream on first use, after their
licence screen has been shown and a typed agreement recorded. On an air-gapped
or metered machine, or when the same model is already installed on another
machine, the bytes can be supplied instead of fetched:

```python
from kilix_content import Installer, verified_packaged_catalog
from kilix_content.first_use import install_with_agreement

spec = verified_packaged_catalog().require_asset("vosk-model-small-en-us-0.15")
installed = install_with_agreement(
    spec,
    installer=Installer("/absolute/user/data/models"),
    store=receipt_store, records=records, texts=texts,
    typed_text=typed_line,          # the same agreement every install needs
    screen=sys.stdout.buffer,
    supplied="/media/usb/vosk-model-small-en-us-0.15",
)
```

`supplied` is a directory holding the asset's installed files **at their
manifest paths** — the layout an installed asset already has, so a tree copied
from another machine can be handed over unchanged. For an archive-sourced
asset that is the extracted archive root; for a converted asset it is the
conversion's output.

This path makes **no network request of any kind**: no fetch, no name lookup,
no connection. Nothing else about it is different. The licence screen, the
typed agreement, the receipt and the coverage check are the same code the
downloading path runs, and the bytes get the same verification:

- every file is opened once, walking each path component below the supplied
  directory relative to its parent with `O_NOFOLLOW` (so no symlink beneath
  it is followed, at any depth), and checked against the manifest's size and
  digest through a descriptor that is never reopened, so a file swapped or
  rewritten between the check and the copy is refused;
- a supplied directory whose path holds a C0, DEL or C1 control character is
  refused before the licence screen is written, because that path is printed
  on the consent screen;
- the licence notices are written from the packaged licence authority, never
  from the supplied directory, so a supplier cannot substitute the text that
  was agreed to;
- the staged tree must match the manifest exactly before it is selected — a
  file the manifest does not list is not installed.

`Installer.ensure_supplied_asset(spec, supplied=..., store=..., records=...,
notices=...)` is the same install without the screen, for a caller that
already holds a covering receipt.

There is no `user-supplied` *source mode* in the catalog, and adding one back
is not how this works: at asset/v3 the manifest determines the installed tree
for every mode alike, so supply is an acquisition available for **all** of
them rather than a record shape that marks a few.

## Converter prerequisites

For explicitly accepted `upstream-convert` models,
`Installer.resolve_converter(spec, report)` resolves system software or builds
the exact packaged Content tool before any model inputs are fetched. It raises
`ConverterPrerequisiteError` when the packaged model needs external software;
the caller can offer a separate opt-in setup step. Content never invokes an
administrator command. Normal model installation also performs this check.

## Packaged catalog verification

`default_catalog()` parses the packaged `plebian.json` without comparing it to
the digest pinned in `kilix_content/receipt.py`. Anything that **acts** on the
catalog — installing an asset, admitting an installed one — should call the
verified entry point instead:

```python
from kilix_content import verified_packaged_catalog

catalog = verified_packaged_catalog()   # refuses unless the bytes are pinned
```

It reads `catalog/plebian.json` **once**, compares those bytes against
`_CATALOG_SHA256` and the frozen asset/v3 schema against
`_ASSET_V3_SCHEMA_SHA256`, raises `RuntimeError` on either mismatch, and then
parses **the bytes it just verified** — it does not re-open the file.

That distinction is the whole value of the entry point, and it is not
theoretical. An earlier shape verified one read and parsed a second, and it
could return a tampered catalog two ways: a tamper landing between the two
reads was never noticed, and because `default_catalog()` is `lru_cache`d, a
caller that had already parsed a tampered file got that **cached** parse back
with no race at all. So `verified_packaged_catalog()` does not call
`default_catalog()` and is deliberately not cached: a cache here is a parse
that can pre-date its own check. `default_catalog()` remains the unverified,
cached parse for callers that only read metadata — never for one that acts on
the catalog.

Both names are part of a **cross-repository contract**: consumers verify the
catalog through this repository and refuse to run when they cannot find the
check. `receipt._verify_frozen_schema` is retained as the same function object
under its old private name for consumers pinned at a gitlink that reaches for
it; do not remove it until they have moved.

## Offline archive cache

Upstream archives may be staged by the operating-system installer in
`/usr/local/share/kilix/model-archives/<archive_sha256>`. The installer checks
that file against the asset's exact archive size and SHA-256 and installs it
through the normal manifest verification and atomic selection path. An absent
entry falls back to the pinned download; a corrupt entry refuses installation.
The cache creates no licence receipt and does not bypass agreement.
`KILIX_CONTENT_ARCHIVE_CACHE` selects another cache directory (an empty value
disables cache lookup). Old archive digests can coexist for rollback.
