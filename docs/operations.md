# Operations

## Local inspection

Run from the root of a Rust workspace:

```text
supplygraph inspect Cargo.lock
supplygraph explain serde --format text
supplygraph export --lockfile Cargo.lock --format json > supplygraph.json
```

Pass `--manifest-path PATH` when the manifest is not adjacent to the lockfile.
Pass each local evidence path explicitly. The tool does not infer a database
from a global cache.

## Reading status

Treat exit status `0` as a complete evidence join. Treat `2` as a report that
requires risk review. Treat `3` as a report that cannot support a complete
conclusion or as an input/command failure. In automation, preserve stdout for
the report and stderr for command errors.

## Reproducibility

Pin the lockfile and evidence files used for a review. Keep the JSON output,
tool version, and source revision together in a private review record. The
report sorts all exposed collections, but the contents still depend on the
exact local Cargo metadata and evidence inputs.

## Privacy

Review output before sharing it. The tool redacts absolute workspace paths in
report fields, but package names, versions, source references, audit criteria,
and evidence summaries may still be sensitive. Do not commit private audit
records or generated reports.

## Failure handling

Malformed lockfiles and evidence files return an error on stderr and exit `3`.
An unavailable Cargo executable or a failed locked metadata command also
returns exit `3`. The tool does not attempt a fallback network fetch or an
automatic repair.
