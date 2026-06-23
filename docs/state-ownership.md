# Metadata Collection State Ownership

This facade is a Frontplane API for vulnerability-intelligence collection. It
does not own Repointel product records: repositories, sources, raw records,
arts, authors, metadata, or relationships remain Repointel-owned and are
accessed through declared `RepointelFacade.*` provider calls.

## Facade-Owned Coordination State

The local metadata-collection store owns records that coordinate analysis work:

- Collection profiles, scenarios, extractor bundles, dictionaries, and rules.
- Collection runs and coverage reports.
- Evidence hits before they are committed downstream.
- Keyword configs for the operator console.
- Score catalog definitions and computed score bucket artifacts.
- SZZ run records returned by `SzzAnalysisProvider.*`.
- Downstream call traces recorded by this facade.
- Downstream service catalog rows used for operator visibility and declared
  Repointel health checks.

These records are local coordination state. They are safe to store in
`METADATA_COLLECTION_DATA_DIR` because they either describe this facade's
analysis policy, track work performed by this facade, or cache provider-call
audit details.

## Provider-Owned State

The following records must not be mutated by hidden local SQL or Node routes:

- Repositories.
- Sources.
- Raw records.
- Arts.
- Authors.
- Repointel metadata.
- Repointel relationships.

Mutations for provider-owned records must cross declared provider calls in
`frontplane.fp`. Evidence commit already uses `RepointelFacade.bulk_upsert_metadata`
and `RepointelFacade.bulk_upsert_relationships`; SZZ Gerrit enrichment now
returns candidate-review details in the SZZ run artifact instead of directly
writing Repointel raw records.

## Routing Boundary

`DownstreamServices` is an operator catalog and connection-test surface. It is
not dynamic provider routing. Generated provider routing is configured through
`METADATACOLLECTIONFACADE_PROVIDER_ENDPOINTS_JSON` and the generated Frontplane
runtime.
