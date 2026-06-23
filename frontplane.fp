namespace repointel.metadata_collection

use fp.std.envelopes.{Page}
use repointel.metadata_collection.backing.{MetadataCollectionRuntime} from "backing/metadata_collection_runtime.rs"

@restApi(base: "/metadata-collection", auth: "Authorization", infer: ["routes", "status", "envelopes", "errors", "contracts", "cli"])
@errors(["BadRequestError", "UnauthorizedError", "ForbiddenError", "ConflictError", "NotFoundError", "ProviderError", "DownstreamServiceError"])
@rateLimit(by: "ip", requests: 600, windowSeconds: 60)
service MetadataCollectionFacade

authz MetadataCollectionPolicy {
  public := true
  reader := auth.authenticated == true
  writer := "writer" in auth.roles || "admin" in auth.roles
  admin := "admin" in auth.roles
}

// This service is intentionally separate from RepointelFacade.
// It owns metadata-collection configuration, runs, evidence hits, coverage, and
// downstream traces. RepointelFacade remains the owner of repositories, sources,
// raw records, arts, authors, metadata items, and relationship edges.
// Outbound Repointel REST edges are declared below and used by Ncall flow steps.

structure ValidationResult := { !valid: Boolean, code: String, message: String, details: Document }
structure PageInfo := { next_cursor: String, total: Long }
structure SearchRequest := { query: String, filters: Document, cursor: String, limit: Integer }
structure IdListRequest := { ids: [String] }
structure ResourceRef := { !type: String, !id: String }
structure DownstreamDocument := { id: String, repository_id: String, source_id: String, created_at: Timestamp, updated_at: Timestamp, doc: Document }
structure DownstreamPage := { items: [Document], page: PageInfo, next_cursor: String, total: Long }
structure DownstreamRawRecord := { id: String, repository_id: String, source_id: String, record_type: String, payload: Document, created_at: Timestamp, updated_at: Timestamp }
structure DownstreamArt := { id: String, repository_id: String, source_id: String, raw_record_id: String, type: String, body: String, payload: Document, created_at: Timestamp, updated_at: Timestamp }

structure DownstreamServiceConfig := { id: String, !name: String, !kind: String, !base_url: Url, auth_mode: String, auth_ref: String, timeout_ms: Integer, retry_policy: Document, enabled: Boolean, created_at: Timestamp, updated_at: Timestamp }
structure DownstreamServiceConfigCreate := { !name: String, !kind: String, !base_url: Url, auth_mode: String, auth_ref: String, timeout_ms: Integer, retry_policy: Document, enabled: Boolean }
structure DownstreamServiceConfigPatch := { !downstream_service_id: String, name: String, base_url: Url, auth_mode: String, auth_ref: String, timeout_ms: Integer, retry_policy: Document, enabled: Boolean }
structure DownstreamServiceConfigPage := { items: [DownstreamServiceConfig], page: PageInfo }
structure DownstreamConnectionTestRequest := { !downstream_service_id: String, params: Document }
structure DownstreamConnectionTestResult := { !ok: Boolean, downstream_service_id: String, service: String, status_code: Integer, latency_ms: Long, message: String, details: Document }
structure DownstreamCallTrace := { id: String, collection_run_id: String, evidence_hit_id: String, downstream_service_id: String, service: String, operation: String, method: String, path: String, request_id: String, status_code: Integer, duration_ms: Long, retry_count: Integer, error: String, created_at: Timestamp }
structure DownstreamCallTracePage := { items: [DownstreamCallTrace], page: PageInfo }

structure CollectionProfile := { id: String, !slug: String, !name: String, description: String, status: String, default_min_confidence: Decimal, review_below_confidence: Decimal, auto_commit_default: Boolean, write_extraction_evidence_metadata: Boolean, created_by: String, created_at: Timestamp, updated_at: Timestamp }
structure CollectionProfileCreate := { !slug: String, !name: String, description: String, default_min_confidence: Decimal, review_below_confidence: Decimal, auto_commit_default: Boolean, write_extraction_evidence_metadata: Boolean }
structure CollectionProfilePatch := { !profile_id: String, slug: String, name: String, description: String, status: String, default_min_confidence: Decimal, review_below_confidence: Decimal, auto_commit_default: Boolean, write_extraction_evidence_metadata: Boolean }
structure CollectionProfilePage := { items: [CollectionProfile], page: PageInfo }

structure CollectionScenario := { id: String, !profile_id: String, !slug: String, !name: String, description: String, priority: Integer, value_tier: String, feasibility_tier: String, source_types: [String], providers: [String], raw_record_types: [String], art_types: [String], required_namespaces: [String], enabled: Boolean, auto_commit_min_confidence: Decimal, review_required_below_confidence: Decimal, created_at: Timestamp, updated_at: Timestamp }
structure CollectionScenarioCreate := { !profile_id: String, !slug: String, !name: String, description: String, priority: Integer, value_tier: String, feasibility_tier: String, source_types: [String], providers: [String], raw_record_types: [String], art_types: [String], required_namespaces: [String], enabled: Boolean, auto_commit_min_confidence: Decimal, review_required_below_confidence: Decimal }
structure CollectionScenarioPatch := { !scenario_id: String, profile_id: String, slug: String, name: String, description: String, priority: Integer, value_tier: String, feasibility_tier: String, source_types: [String], providers: [String], raw_record_types: [String], art_types: [String], required_namespaces: [String], enabled: Boolean, auto_commit_min_confidence: Decimal, review_required_below_confidence: Decimal }
structure CollectionScenarioPage := { items: [CollectionScenario], page: PageInfo }

structure ExtractorBundle := { id: String, !profile_id: String, !slug: String, !name: String, description: String, version: String, provider: String, source_type: String, raw_record_types: [String], art_types: [String], status: String, enabled: Boolean, rules_count: Integer, created_at: Timestamp, updated_at: Timestamp }
structure ExtractorBundleCreate := { !profile_id: String, !slug: String, !name: String, description: String, !version: String, provider: String, source_type: String, raw_record_types: [String], art_types: [String], status: String, enabled: Boolean }
structure ExtractorBundlePatch := { !bundle_id: String, profile_id: String, slug: String, name: String, description: String, version: String, provider: String, source_type: String, raw_record_types: [String], art_types: [String], status: String, enabled: Boolean }
structure ExtractorBundlePage := { items: [ExtractorBundle], page: PageInfo }

structure ExtractorDictionaryEntry := { !key: String, label: String, category: String, severity: String, patterns: [String], metadata: Document }
structure ExtractorDictionary := { id: String, !slug: String, !name: String, description: String, version: String, kind: String, entries: [ExtractorDictionaryEntry], enabled: Boolean, created_at: Timestamp, updated_at: Timestamp }
structure ExtractorDictionaryCreate := { !slug: String, !name: String, description: String, version: String, kind: String, entries: [ExtractorDictionaryEntry], enabled: Boolean }
structure ExtractorDictionaryPatch := { !dictionary_id: String, slug: String, name: String, description: String, version: String, kind: String, entries: [ExtractorDictionaryEntry], enabled: Boolean }
structure ExtractorDictionaryPage := { items: [ExtractorDictionary], page: PageInfo }

structure ExtractorOutputMetadata := { !local_ref: String, subject_strategy: String, subject_type: String, subject_id_template: String, !namespace: String, !key: String, !value_type: String, value_template: Document, canonicalize: String, as_canonical_node: Boolean, source_created_at_strategy: String, source_updated_at_strategy: String }
structure ExtractorOutputEndpoint := { !type: String, id_template: String, metadata_local_ref: String }
structure ExtractorOutputRelationship := { !local_ref: String, !from: ExtractorOutputEndpoint, !relation: String, !to: ExtractorOutputEndpoint, direction: String, confidence_template: Decimal, evidence_art_strategy: String, evidence_art_id_template: String, evidence_metadata_local_ref: String, origin_template: String }

structure ExtractorRule := { id: String, !bundle_id: String, scenario_id: String, !slug: String, !name: String, description: String, !version: String, type: String, enabled: Boolean, provider: String, source_type: String, raw_record_types: [String], art_types: [String], field_paths: [String], pattern: String, patterns: [String], dictionary_id: String, parser_ref: String, json_path: String, yaml_path: String, when: Document, params: Document, outputs_metadata: [ExtractorOutputMetadata], outputs_relationships: [ExtractorOutputRelationship], min_confidence: Decimal, default_confidence: Decimal, review_required_below_confidence: Decimal, created_at: Timestamp, updated_at: Timestamp }
structure ExtractorRuleCreate := { !bundle_id: String, scenario_id: String, !slug: String, !name: String, description: String, !version: String, !type: String, enabled: Boolean, provider: String, source_type: String, raw_record_types: [String], art_types: [String], field_paths: [String], pattern: String, patterns: [String], dictionary_id: String, parser_ref: String, json_path: String, yaml_path: String, when: Document, params: Document, outputs_metadata: [ExtractorOutputMetadata], outputs_relationships: [ExtractorOutputRelationship], min_confidence: Decimal, default_confidence: Decimal, review_required_below_confidence: Decimal }
structure ExtractorRulePatch := { !rule_id: String, bundle_id: String, scenario_id: String, slug: String, name: String, description: String, version: String, type: String, enabled: Boolean, provider: String, source_type: String, raw_record_types: [String], art_types: [String], field_paths: [String], pattern: String, patterns: [String], dictionary_id: String, parser_ref: String, json_path: String, yaml_path: String, when: Document, params: Document, outputs_metadata: [ExtractorOutputMetadata], outputs_relationships: [ExtractorOutputRelationship], min_confidence: Decimal, default_confidence: Decimal, review_required_below_confidence: Decimal }
structure ExtractorRulePage := { items: [ExtractorRule], page: PageInfo }
structure RuleTestRequest := { !rule_id: String, repository_id: String, source_id: String, sample_raw_record_id: String, sample_art_id: String, sample_payload: Document, sample_body: String, commit: Boolean, params: Document }
structure RuleTestResult := { !ok: Boolean, rule_id: String, rule_version: String, evidence_hits: [EvidenceHit], proposed_metadata_count: Integer, proposed_relationships_count: Integer, logs: [String], details: Document }

structure CollectionSourceSelector := { repository_group_id: String, repository_id: String, source_ids: [String], source_types: [String], providers: [String], raw_record_ids: [String], raw_record_types: [String], art_ids: [String], art_types: [String], author_ids: [String], since: Timestamp, until: Timestamp, query: String, filters: Document, cursor: String, limit: Integer }
structure CollectionPlanRequest := { !profile_id: String, selector: CollectionSourceSelector, scenario_ids: [String], bundle_ids: [String], rule_ids: [String], dry_run: Boolean, params: Document }
structure CollectionPlan := { id: String, profile_id: String, selector: CollectionSourceSelector, repositories_count: Integer, sources_count: Integer, raw_records_count: Integer, arts_count: Integer, authors_count: Integer, scenarios_count: Integer, bundles_count: Integer, rules_count: Integer, estimated_work_units: Long, can_run: Boolean, warnings: [String], gaps: [String], created_at: Timestamp }
structure CollectionRunRequest := { !profile_id: String, selector: CollectionSourceSelector, scenario_ids: [String], bundle_ids: [String], rule_ids: [String], requested_by: String, mode: String, dry_run: Boolean, auto_commit: Boolean, min_confidence: Decimal, review_below_confidence: Decimal, priority: Integer, params: Document }
structure CollectionRun := { id: String, profile_id: String, repository_group_id: String, repository_id: String, requested_by: String, status: String, mode: String, dry_run: Boolean, auto_commit: Boolean, min_confidence: Decimal, review_below_confidence: Decimal, priority: Integer, cursor: String, watermark: String, started_at: Timestamp, finished_at: Timestamp, duration_ms: Long, sources_scanned_count: Integer, raw_records_scanned_count: Integer, arts_scanned_count: Integer, authors_scanned_count: Integer, evidence_hits_count: Integer, accepted_hits_count: Integer, rejected_hits_count: Integer, review_hits_count: Integer, metadata_proposed_count: Integer, relationships_proposed_count: Integer, metadata_upserted_count: Integer, relationships_upserted_count: Integer, downstream_calls_count: Integer, downstream_errors_count: Integer, error: String, stats: Document, created_at: Timestamp, updated_at: Timestamp }
structure CollectionRunPatch := { !collection_run_id: String, status: String, cursor: String, watermark: String, auto_commit: Boolean, min_confidence: Decimal, review_below_confidence: Decimal, priority: Integer, error: String, stats: Document }
structure CollectionRunPage := { items: [CollectionRun], page: PageInfo }

structure ProposedMetadataWrite := { !local_ref: String, repository_id: String, source_id: String, ingestion_job_id: String, raw_record_id: String, subject_type: String, subject_id: String, !namespace: String, !key: String, value: Document, !value_type: String, source_created_at: Timestamp, source_updated_at: Timestamp, dedupe_key: String, role: String }
structure ProposedRelationshipEndpoint := { !type: String, id: String, metadata_local_ref: String }
structure ProposedRelationshipWrite := { !local_ref: String, repository_id: String, source_id: String, ingestion_job_id: String, raw_record_id: String, !from: ProposedRelationshipEndpoint, !relation: String, !to: ProposedRelationshipEndpoint, direction: String, confidence: Decimal, evidence_art_id: String, evidence_metadata_local_ref: String, origin: String, dedupe_key: String }
structure EvidenceHit := { id: String, collection_run_id: String, profile_id: String, scenario_id: String, bundle_id: String, rule_id: String, rule_version: String, repository_id: String, source_id: String, ingestion_job_id: String, raw_record_id: String, art_id: String, author_id: String, source_kind: String, source_field_path: String, evidence_span_start: Integer, evidence_span_end: Integer, matched_text_hash: String, matched_text_preview: String, namespace: String, key: String, value: Document, value_type: String, canonical_value: Document, value_hash: String, confidence: Decimal, disposition: String, disposition_reason: String, origin: String, hit_hash: String, proposed_metadata: [ProposedMetadataWrite], proposed_relationships: [ProposedRelationshipWrite], committed_metadata_ids: [String], committed_relationship_ids: [String], reviewer: String, reviewer_note: String, reviewed_at: Timestamp, created_at: Timestamp, updated_at: Timestamp }
structure EvidenceHitPatch := { !evidence_hit_id: String, confidence: Decimal, disposition: String, disposition_reason: String, reviewer_note: String }
structure EvidenceHitBulkReviewRequest := { evidence_hit_ids: [String], collection_run_id: String, disposition: String, disposition_reason: String, reviewer_note: String, filters: Document }
structure EvidenceHitBulkReviewResult := { !ok: Boolean, reviewed_count: Integer, skipped_count: Integer, errors: [String], details: Document }
structure EvidenceHitPage := { items: [EvidenceHit], page: PageInfo }
structure CommitEvidenceHitsRequest := { collection_run_id: String, evidence_hit_ids: [String], disposition_filter: String, min_confidence: Decimal, dry_run: Boolean, write_extraction_evidence_metadata: Boolean, params: Document }
structure CommitEvidenceHitsResult := { !ok: Boolean, collection_run_id: String, evidence_hits_committed_count: Integer, metadata_upserted_count: Integer, relationships_upserted_count: Integer, skipped_count: Integer, failed_count: Integer, downstream_calls: [DownstreamCallTrace], errors: [String], details: Document }

structure ScenarioCoverageReportRequest := { !profile_id: String, selector: CollectionSourceSelector, scenario_ids: [String], params: Document }
structure ScenarioCoverage := { scenario_id: String, scenario_slug: String, priority: Integer, feasible: Boolean, sources_available: Boolean, rules_enabled: Boolean, raw_records_available_count: Integer, arts_available_count: Integer, evidence_hits_count: Integer, committed_metadata_count: Integer, committed_relationships_count: Integer, gaps: [String] }
structure ScenarioCoverageReport := { id: String, profile_id: String, repository_group_id: String, repository_id: String, source_ids: [String], scenarios: [ScenarioCoverage], gaps: [String], generated_at: Timestamp }
structure ScenarioCoverageReportPage := { items: [ScenarioCoverageReport], page: PageInfo }

structure Score := { !id: String, !slug: String, !name: String, description: String, subject_type: String, value_type: String, direction: String, range: Document, default_weight: Decimal, missing_policy: String, inputs: [String], bucket: String, version: String, metadata: Document }
structure ScorePage := { items: [Score], page: PageInfo }
structure ScoreComputeRequest := { score_id: String, subject_id: String, score: Decimal, value: Document, confidence: Decimal, params: Document }
structure ScoreComputeResult := { !score_id: String, subject_id: String, score: Decimal, confidence: Decimal, normalized: Boolean, details: Document }
structure ScoreBucketItem := { !score_id: String, weight: Decimal, required: Boolean }
structure ScoreBucket := { !id: String, !slug: String, !name: String, description: String, subject_type: String, aggregation: String, output_range: Document, scores: [ScoreBucketItem], version: String, metadata: Document }
structure ScoreBucketPage := { items: [ScoreBucket], page: PageInfo }
structure ScoreInput := { !score_id: String, subject_id: String, score: Decimal, value: Document, confidence: Decimal, weight: Decimal, params: Document }
structure ScoreBucketComputeRequest := { score_bucket_id: String, subject_id: String, items: [ScoreInput], params: Document }
structure ScoreBucketComputeResult := { !score_bucket_id: String, subject_id: String, score: Decimal, aggregation: String, items: [ScoreComputeResult], missing_score_ids: [String], denominator: Decimal, details: Document }
structure KeywordRule := { !id: String, label: String, !pattern: String, color: String, weight: Integer, order: Integer, enabled: Boolean }
structure KeywordConfig := { !id: String, keyword_config_id: String, repository_id: String, keyword_score_cap: Integer, rules: [KeywordRule], updated_at: Timestamp }
structure KeywordConfigPage := { items: [KeywordConfig], page: PageInfo }
structure KeywordConfigResolveRequest := { repository_id: String }
structure KeywordConfigSaveRequest := { repository_id: String, rules: [KeywordRule] }
structure KeywordConfigAdjustRequest := { repository_id: String, !keyword_id: String, !delta: Integer }
structure ConsoleConfig := { repointelBase: String, metadataCollectionBase: String, analyticsAvailable: Boolean, repointelProxy: String, metadataCollectionProxy: String }
structure ConsoleReportRequest := { min_commits: String, min_approvals: String, repository_id: String, project: String, status: String, month: String, since: String, until: String, date_field: String, limit: String, refresh: String, q: String, name: String, last_name: String, email: String, author_id: String, external_author_id: String, gerrit_account_id: String, change_number: String, include_bugs: String, bug_limit: String, review_limit: String, commit_limit: String, min_score: String }
structure ConsoleReport := Document

structure SzzAnalysisSelector := { repository_group_id: String, repository_id: String, repository_name: String, review_ids: [String], limit: Integer, latest: Boolean, status: String, bug_link_policy: String, since: Timestamp, until: Timestamp, filters: Document }
structure SzzAnalysisRequest := { szz_analysis_id: String, selector: SzzAnalysisSelector, review_id: String, repository_id: String, repository_name: String, commit_sha: String, min_direct_lines: Integer, min_context_lines: Integer, include_context_candidates: Boolean, backfill_missing_reviews: Boolean, commit_evidence: Boolean, force: Boolean, dry_run: Boolean, params: Document }
structure SzzActor := { name: String, email: String, username: String, account_id: String, author_id: String, identity_key: String, metadata: Document }
structure SzzCandidateReview := { change_number: String, status: String, subject: String, url: Url, change_id: String, current_revision: String, found_in_db: Boolean, backfilled: Boolean }
structure SzzCandidate := { !type: String, !lines: Integer, !score: Decimal, confidence: String, candidate_commit: String, candidate_change_id: String, author: SzzActor, candidate_review: SzzCandidateReview, approvers: [SzzActor], files: [String], reason: String, evidence: [Document], metadata: Document }
structure SzzAnalysisSummary := { selected_reviews: Integer, analyzed_reviews: Integer, skipped_reviews: Integer, candidate_rows_kept: Integer, direct_rows: Integer, context_rows: Integer, unique_candidate_commits: Integer, rows_with_review: Integer, rows_with_approver: Integer, unique_reviews_backfilled: Integer, evidence_hits_count: Integer, errors: Integer, details: Document }
structure SzzRun := { id: String, selector: SzzAnalysisSelector, status: String, mode: String, szz_version: String, bug_link_policy: String, min_direct_lines: Integer, min_context_lines: Integer, include_context_candidates: Boolean, backfill_missing_reviews: Boolean, commit_evidence: Boolean, cache_key: String, review_id: String, repository_id: String, repository_name: String, commit_sha: String, candidates: [SzzCandidate], evidence_hits: [EvidenceHit], summary: SzzAnalysisSummary, errors: [String], artifacts: Document, generated_at: Timestamp, created_at: Timestamp, updated_at: Timestamp }
structure SzzRunPage := { items: [SzzRun], page: PageInfo }

structure RepointelMetadataUpsert := { repository_id: String, source_id: String, ingestion_job_id: String, raw_record_id: String, subject_type: String, subject_id: String, namespace: String, key: String, value: Document, value_type: String, source_created_at: Timestamp, source_updated_at: Timestamp }
structure RepointelMetadataBulkUpsertRequest := { !items: [RepointelMetadataUpsert], _frontplane_auth_token: String }
structure RepointelRelationshipEndpoint := { !type: String, id: String, metadata_local_ref: String }
structure RepointelRelationshipUpsert := { repository_id: String, source_id: String, ingestion_job_id: String, raw_record_id: String, from_type: String, from_id: String, to_type: String, to_id: String, relation: String, direction: String, confidence: Decimal, evidence_art_id: String, evidence_metadata_id: String, origin: String }
structure RepointelRelationshipBulkUpsertRequest := { !relationships: [RepointelRelationshipUpsert], _frontplane_auth_token: String }

rest RepointelFacade.health(input: Document, output: Document, method: "GET", path: "/healthz", auth: "none")
rest RepointelFacade.search_sources(input: SearchRequest, output: DownstreamPage, method: "POST", path: "/sources:search", auth: "bearer")
rest RepointelFacade.search_raw_records(input: SearchRequest, output: DownstreamPage, method: "POST", path: "/raw-records:search", auth: "bearer")
rest RepointelFacade.search_arts(input: SearchRequest, output: DownstreamPage, method: "POST", path: "/arts:search", auth: "bearer")
rest RepointelFacade.search_authors(input: SearchRequest, output: DownstreamPage, method: "POST", path: "/authors:search", auth: "bearer")
rest RepointelFacade.get_raw_record(input: { raw_record_id: String, _frontplane_auth_token: String }, output: DownstreamRawRecord, method: "GET", path: "/raw-records/{raw_record_id}", auth: "bearer")
rest RepointelFacade.get_art(input: { art_id: String, _frontplane_auth_token: String }, output: DownstreamArt, method: "GET", path: "/arts/{art_id}", auth: "bearer")
rest RepointelFacade.bulk_upsert_metadata(input: RepointelMetadataBulkUpsertRequest, output: DownstreamPage, method: "POST", path: "/metadata:bulk-upsert", auth: "bearer")
rest RepointelFacade.bulk_upsert_relationships(input: RepointelRelationshipBulkUpsertRequest, output: DownstreamPage, method: "POST", path: "/relationships:bulk-upsert", auth: "bearer")
rest RepointelAnalyticsProvider.get_analytics(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-analytics", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_author_history(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-author-history", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_ideas_base(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-ideas-base", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_loci(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-loci", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_loci_extended(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-loci-extended", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_review_risk(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-review-risk", auth: "repointel-analytics-provider-token")
rest RepointelAnalyticsProvider.get_review_risk_messages(input: ConsoleReportRequest, output: ConsoleReport, method: "GET", path: "/analytics/repointel-review-risk-messages", auth: "repointel-analytics-provider-token")
rest SzzAnalysisProvider.analyze_review(input: SzzAnalysisRequest, output: SzzRun, method: "POST", path: "/szz/analyze-review", auth: "repointel-szz-provider-token")
rest SzzAnalysisProvider.analyze_batch(input: SzzAnalysisRequest, output: SzzRun, method: "POST", path: "/szz/analyze-batch", auth: "repointel-szz-provider-token")

@resource(member: "downstream_service", key: "downstream_service_id", collection: "downstream-services", entity: DownstreamServiceConfig)
resource DownstreamServices {
  @list(authz: admin, DGcall: MetadataCollectionRuntime.list_downstream_services(input) -> downstream_service_configs, output: downstream_service_configs)
  @create(input: DownstreamServiceConfigCreate, authz: admin, DGcall: MetadataCollectionRuntime.create_downstream_service(input) -> downstream_service, code: 201, output: downstream_service)
  @get(input: { downstream_service_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.get_downstream_service(input) -> downstream_service, output: downstream_service)
  @update(input: DownstreamServiceConfigPatch, authz: admin, DGcall: MetadataCollectionRuntime.update_downstream_service(input) -> downstream_service, output: downstream_service)
  @delete(input: { downstream_service_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_downstream_service(input) -> deleted, output: none)
  @memberAction("test-connection", operation: "TestDownstreamServiceConnection", input: DownstreamConnectionTestRequest, authz: admin, DGcall: MetadataCollectionRuntime.prepare_repointel_health(input) -> repointel_health_request, Ncall: RepointelFacade.health(repointel_health_request) -> downstream_health, DGcall: MetadataCollectionRuntime.record_downstream_service_connection_test(input, downstream_health) -> downstream_connection_test_result, output: downstream_connection_test_result)
}

@resource(member: "profile", key: "profile_id", collection: "profiles", entity: CollectionProfile)
resource CollectionProfiles {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_profiles(input) -> collection_profiles, output: collection_profiles)
  @create(input: CollectionProfileCreate, authz: admin, DGcall: MetadataCollectionRuntime.create_profile(input) -> profile, code: 201, output: profile)
  @get(input: { profile_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_profile(input) -> profile, output: profile)
  @update(input: CollectionProfilePatch, authz: admin, DGcall: MetadataCollectionRuntime.update_profile(input) -> profile, output: profile)
  @delete(input: { profile_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_profile(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchCollectionProfiles", method: "POST", path: "/profiles:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_profiles(input) -> collection_profiles, output: collection_profiles)
  @collectionAction("seed-vuln-intel-priority-v1", operation: "SeedVulnIntelPriorityProfile", method: "POST", path: "/profiles:seed-vuln-intel-priority-v1", input: { force: Boolean }, authz: admin, DGcall: MetadataCollectionRuntime.seed_vuln_intel_priority_profile(input) -> profile, output: profile)
  @memberAction("scenarios", operation: "GetCollectionProfileScenarios", method: "GET", input: { profile_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_profile_scenarios(input) -> collection_scenarios, output: collection_scenarios)
  @memberAction("bundles", operation: "GetCollectionProfileBundles", method: "GET", input: { profile_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_profile_bundles(input) -> extractor_bundles, output: extractor_bundles)
}

@resource(member: "scenario", key: "scenario_id", collection: "scenarios", entity: CollectionScenario)
resource CollectionScenarios {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_scenarios(input) -> collection_scenarios, output: collection_scenarios)
  @create(input: CollectionScenarioCreate, authz: admin, DGcall: MetadataCollectionRuntime.create_scenario(input) -> scenario, code: 201, output: scenario)
  @get(input: { scenario_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_scenario(input) -> scenario, output: scenario)
  @update(input: CollectionScenarioPatch, authz: admin, DGcall: MetadataCollectionRuntime.update_scenario(input) -> scenario, output: scenario)
  @delete(input: { scenario_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_scenario(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchCollectionScenarios", method: "POST", path: "/scenarios:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_scenarios(input) -> collection_scenarios, output: collection_scenarios)
  @memberAction("rules", operation: "GetCollectionScenarioRules", method: "GET", input: { scenario_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_scenario_rules(input) -> extractor_rules, output: extractor_rules)
}

@resource(member: "dictionary", key: "dictionary_id", collection: "dictionaries", entity: ExtractorDictionary)
resource ExtractorDictionaries {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_dictionaries(input) -> extractor_dictionaries, output: extractor_dictionaries)
  @create(input: ExtractorDictionaryCreate, authz: admin, DGcall: MetadataCollectionRuntime.create_dictionary(input) -> dictionary, code: 201, output: dictionary)
  @get(input: { dictionary_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_dictionary(input) -> dictionary, output: dictionary)
  @update(input: ExtractorDictionaryPatch, authz: admin, DGcall: MetadataCollectionRuntime.update_dictionary(input) -> dictionary, output: dictionary)
  @delete(input: { dictionary_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_dictionary(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchExtractorDictionaries", method: "POST", path: "/dictionaries:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_dictionaries(input) -> extractor_dictionaries, output: extractor_dictionaries)
}

@resource(member: "bundle", key: "bundle_id", collection: "extractor-bundles", entity: ExtractorBundle)
resource ExtractorBundles {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_bundles(input) -> extractor_bundles, output: extractor_bundles)
  @create(input: ExtractorBundleCreate, authz: admin, DGcall: MetadataCollectionRuntime.create_bundle(input) -> bundle, code: 201, output: bundle)
  @get(input: { bundle_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_bundle(input) -> bundle, output: bundle)
  @update(input: ExtractorBundlePatch, authz: admin, DGcall: MetadataCollectionRuntime.update_bundle(input) -> bundle, output: bundle)
  @delete(input: { bundle_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_bundle(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchExtractorBundles", method: "POST", path: "/extractor-bundles:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_bundles(input) -> extractor_bundles, output: extractor_bundles)
  @memberAction("enable", operation: "EnableExtractorBundle", input: { bundle_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.enable_bundle(input) -> bundle, output: bundle)
  @memberAction("disable", operation: "DisableExtractorBundle", input: { bundle_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.disable_bundle(input) -> bundle, output: bundle)
  @memberAction("rules", operation: "GetExtractorBundleRules", method: "GET", input: { bundle_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_bundle_rules(input) -> extractor_rules, output: extractor_rules)
}

@resource(member: "rule", key: "rule_id", collection: "extractor-rules", entity: ExtractorRule)
resource ExtractorRules {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_rules(input) -> extractor_rules, output: extractor_rules)
  @create(input: ExtractorRuleCreate, authz: admin, Lcall: MetadataCollectionRuntime.validate_extractor_rule(input) -> validation, if: (validation.valid == true, pass, reject BadRequestError), DGcall: MetadataCollectionRuntime.create_rule(input) -> rule, code: 201, output: rule)
  @get(input: { rule_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_rule(input) -> rule, output: rule)
  @update(input: ExtractorRulePatch, authz: admin, Lcall: MetadataCollectionRuntime.validate_extractor_rule_patch(input) -> validation, if: (validation.valid == true, pass, reject BadRequestError), DGcall: MetadataCollectionRuntime.update_rule(input) -> rule, output: rule)
  @delete(input: { rule_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_rule(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchExtractorRules", method: "POST", path: "/extractor-rules:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_rules(input) -> extractor_rules, output: extractor_rules)
  @memberAction("enable", operation: "EnableExtractorRule", input: { rule_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.enable_rule(input) -> rule, output: rule)
  @memberAction("disable", operation: "DisableExtractorRule", input: { rule_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.disable_rule(input) -> rule, output: rule)
  @memberAction("test", operation: "TestExtractorRule", input: RuleTestRequest, authz: writer, LEcall: MetadataCollectionRuntime.test_rule(input) -> rule_test_result, output: rule_test_result)
}

@resource(member: "collection_run", key: "collection_run_id", collection: "runs", entity: CollectionRun)
resource CollectionRuns {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_runs(input) -> collection_runs, output: collection_runs)
  @create(input: CollectionRunRequest, authz: writer, Lcall: MetadataCollectionRuntime.validate_collection_run_request(input) -> validation, if: (validation.valid == true, pass, reject BadRequestError), DGcall: MetadataCollectionRuntime.prepare_repointel_search_sources(input) -> repointel_sources_request, Ncall: RepointelFacade.search_sources(repointel_sources_request) -> downstream_sources_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_raw_records(input) -> repointel_raw_records_request, Ncall: RepointelFacade.search_raw_records(repointel_raw_records_request) -> downstream_raw_records_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_arts(input) -> repointel_arts_request, Ncall: RepointelFacade.search_arts(repointel_arts_request) -> downstream_arts_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_authors(input) -> repointel_authors_request, Ncall: RepointelFacade.search_authors(repointel_authors_request) -> downstream_authors_page, DGcall: MetadataCollectionRuntime.create_run(input, downstream_sources_page, downstream_raw_records_page, downstream_arts_page, downstream_authors_page) -> collection_run, code: 202, output: collection_run)
  @get(input: { collection_run_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_run(input) -> collection_run, output: collection_run)
  @update(input: CollectionRunPatch, authz: writer, DGcall: MetadataCollectionRuntime.update_run(input) -> collection_run, output: collection_run)
  @delete(input: { collection_run_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_run(input) -> deleted, output: none)
  @collectionAction("plan", operation: "PlanMetadataCollectionRun", method: "POST", path: "/runs:plan", input: CollectionPlanRequest, authz: reader, DGcall: MetadataCollectionRuntime.prepare_repointel_search_sources(input) -> repointel_sources_request, Ncall: RepointelFacade.search_sources(repointel_sources_request) -> downstream_sources_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_raw_records(input) -> repointel_raw_records_request, Ncall: RepointelFacade.search_raw_records(repointel_raw_records_request) -> downstream_raw_records_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_arts(input) -> repointel_arts_request, Ncall: RepointelFacade.search_arts(repointel_arts_request) -> downstream_arts_page, DGcall: MetadataCollectionRuntime.prepare_repointel_search_authors(input) -> repointel_authors_request, Ncall: RepointelFacade.search_authors(repointel_authors_request) -> downstream_authors_page, DGcall: MetadataCollectionRuntime.plan_run(input, downstream_sources_page, downstream_raw_records_page, downstream_arts_page, downstream_authors_page) -> collection_plan, output: collection_plan)
  @collectionAction("search", operation: "SearchMetadataCollectionRuns", method: "POST", path: "/runs:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_runs(input) -> collection_runs, output: collection_runs)
  @memberAction("cancel", operation: "CancelMetadataCollectionRun", input: { collection_run_id: String }, authz: writer, DGcall: MetadataCollectionRuntime.cancel_run(input) -> collection_run, output: collection_run)
  @memberAction("pause", operation: "PauseMetadataCollectionRun", input: { collection_run_id: String }, authz: writer, DGcall: MetadataCollectionRuntime.pause_run(input) -> collection_run, output: collection_run)
  @memberAction("resume", operation: "ResumeMetadataCollectionRun", input: { collection_run_id: String }, authz: writer, DGcall: MetadataCollectionRuntime.resume_run(input) -> collection_run, code: 202, output: collection_run)
  @memberAction("retry", operation: "RetryMetadataCollectionRun", input: { collection_run_id: String }, authz: writer, DGcall: MetadataCollectionRuntime.retry_run(input) -> collection_run, code: 202, output: collection_run)
  @memberAction("evidence-hits", operation: "GetCollectionRunEvidenceHits", method: "GET", input: { collection_run_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_run_evidence_hits(input) -> evidence_hits, output: evidence_hits)
  @memberAction("commit", operation: "CommitCollectionRunEvidenceHits", input: CommitEvidenceHitsRequest, authz: writer, DGcall: MetadataCollectionRuntime.prepare_metadata_bulk_upsert(input) -> metadata_bulk_upsert_request, Ncall: RepointelFacade.bulk_upsert_metadata(metadata_bulk_upsert_request) -> downstream_metadata_page, DGcall: MetadataCollectionRuntime.prepare_relationship_bulk_upsert(input, downstream_metadata_page) -> relationship_bulk_upsert_request, Lcall: MetadataCollectionRuntime.validate_relationship_bulk_upsert_request(relationship_bulk_upsert_request) -> validation, if: (validation.valid == true, pass, reject BadRequestError), Ncall: RepointelFacade.bulk_upsert_relationships(relationship_bulk_upsert_request) -> downstream_relationship_page, DGcall: MetadataCollectionRuntime.finish_commit(input, downstream_metadata_page, downstream_relationship_page) -> commit_evidence_hits_result, output: commit_evidence_hits_result)
  @memberAction("downstream-calls", operation: "GetCollectionRunDownstreamCalls", method: "GET", input: { collection_run_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_run_downstream_calls(input) -> downstream_call_traces, output: downstream_call_traces)
}

@resource(member: "evidence_hit", key: "evidence_hit_id", collection: "evidence-hits", entity: EvidenceHit)
resource EvidenceHits {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_evidence_hits(input) -> evidence_hits, output: evidence_hits)
  @get(input: { evidence_hit_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_evidence_hit(input) -> evidence_hit, output: evidence_hit)
  @update(input: EvidenceHitPatch, authz: writer, DGcall: MetadataCollectionRuntime.update_evidence_hit(input) -> evidence_hit, output: evidence_hit)
  @collectionAction("search", operation: "SearchEvidenceHits", method: "POST", path: "/evidence-hits:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_evidence_hits(input) -> evidence_hits, output: evidence_hits)
  @collectionAction("bulk-review", operation: "BulkReviewEvidenceHits", method: "POST", path: "/evidence-hits:bulk-review", input: EvidenceHitBulkReviewRequest, authz: writer, DGcall: MetadataCollectionRuntime.bulk_review_evidence_hits(input) -> evidence_hit_bulk_review_result, output: evidence_hit_bulk_review_result)
  @collectionAction("commit", operation: "CommitEvidenceHits", method: "POST", path: "/evidence-hits:commit", input: CommitEvidenceHitsRequest, authz: writer, DGcall: MetadataCollectionRuntime.prepare_metadata_bulk_upsert(input) -> metadata_bulk_upsert_request, Ncall: RepointelFacade.bulk_upsert_metadata(metadata_bulk_upsert_request) -> downstream_metadata_page, DGcall: MetadataCollectionRuntime.prepare_relationship_bulk_upsert(input, downstream_metadata_page) -> relationship_bulk_upsert_request, Lcall: MetadataCollectionRuntime.validate_relationship_bulk_upsert_request(relationship_bulk_upsert_request) -> validation, if: (validation.valid == true, pass, reject BadRequestError), Ncall: RepointelFacade.bulk_upsert_relationships(relationship_bulk_upsert_request) -> downstream_relationship_page, DGcall: MetadataCollectionRuntime.finish_commit(input, downstream_metadata_page, downstream_relationship_page) -> commit_evidence_hits_result, output: commit_evidence_hits_result)
  @memberAction("accept", operation: "AcceptEvidenceHit", input: { evidence_hit_id: String }, authz: writer, DGcall: MetadataCollectionRuntime.accept_evidence_hit(input) -> evidence_hit, output: evidence_hit)
  @memberAction("reject", operation: "RejectEvidenceHit", input: { evidence_hit_id: String, reason: String }, authz: writer, DGcall: MetadataCollectionRuntime.reject_evidence_hit(input) -> evidence_hit, output: evidence_hit)
  @memberAction("raw-record", operation: "GetEvidenceHitRawRecord", method: "GET", input: { evidence_hit_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.prepare_evidence_hit_raw_record(input) -> raw_record_request, Ncall: RepointelFacade.get_raw_record(raw_record_request) -> downstream_raw_record, DGcall: MetadataCollectionRuntime.record_evidence_hit_downstream_read(input, downstream_raw_record) -> downstream_raw_record, output: downstream_raw_record)
  @memberAction("art", operation: "GetEvidenceHitArt", method: "GET", input: { evidence_hit_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.prepare_evidence_hit_art(input) -> art_request, Ncall: RepointelFacade.get_art(art_request) -> downstream_art, DGcall: MetadataCollectionRuntime.record_evidence_hit_downstream_read(input, downstream_art) -> downstream_art, output: downstream_art)
}

@resource(member: "coverage_report", key: "coverage_report_id", collection: "coverage-reports", entity: ScenarioCoverageReport)
resource ScenarioCoverageReports {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_coverage_reports(input) -> scenario_coverage_reports, output: scenario_coverage_reports)
  @create(input: ScenarioCoverageReportRequest, authz: reader, DGcall: MetadataCollectionRuntime.create_coverage_report(input) -> scenario_coverage_report, code: 201, output: scenario_coverage_report)
  @get(input: { coverage_report_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_coverage_report(input) -> scenario_coverage_report, output: scenario_coverage_report)
  @delete(input: { coverage_report_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_coverage_report(input) -> deleted, output: none)
  @collectionAction("latest", operation: "GetLatestScenarioCoverageReport", method: "POST", path: "/coverage-reports:latest", input: ScenarioCoverageReportRequest, authz: reader, DGcall: MetadataCollectionRuntime.get_latest_coverage_report(input) -> scenario_coverage_report, output: scenario_coverage_report)
}

@resource(member: "score", key: "score_id", collection: "scores", entity: Score)
resource Scores {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_scores(input) -> scores, output: scores)
  @get(input: { score_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_score(input) -> score, output: score)
  @memberAction("compute", operation: "ComputeScore", input: ScoreComputeRequest, authz: reader, DGcall: MetadataCollectionRuntime.compute_score(input) -> score_compute_result, output: score_compute_result)
}

@resource(member: "score_bucket", key: "score_bucket_id", collection: "score_buckets", entity: ScoreBucket)
resource ScoreBuckets {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_score_buckets(input) -> score_buckets, output: score_buckets)
  @get(input: { score_bucket_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_score_bucket(input) -> score_bucket, output: score_bucket)
  @memberAction("compute", operation: "ComputeScoreBucket", input: ScoreBucketComputeRequest, authz: reader, DGcall: MetadataCollectionRuntime.compute_score_bucket(input) -> score_bucket_compute_result, output: score_bucket_compute_result)
}

@resource(member: "keyword_config", key: "keyword_config_id", collection: "keyword-configs", entity: KeywordConfig)
resource KeywordConfigs {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_keyword_configs(input) -> keyword_configs, output: keyword_configs)
  @get(input: { keyword_config_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_keyword_config(input) -> keyword_config, output: keyword_config)
  @collectionAction("resolve", operation: "ResolveKeywordConfig", method: "POST", path: "/keyword-configs:resolve", input: KeywordConfigResolveRequest, authz: reader, DGcall: MetadataCollectionRuntime.resolve_keyword_config(input) -> keyword_config, output: keyword_config)
  @collectionAction("save", operation: "SaveKeywordConfig", method: "POST", path: "/keyword-configs:save", input: KeywordConfigSaveRequest, authz: writer, DGcall: MetadataCollectionRuntime.save_keyword_config(input) -> keyword_config, output: keyword_config)
  @collectionAction("adjust", operation: "AdjustKeywordConfig", method: "POST", path: "/keyword-configs:adjust", input: KeywordConfigAdjustRequest, authz: writer, DGcall: MetadataCollectionRuntime.adjust_keyword_config(input) -> keyword_config, output: keyword_config)
}

@resource(member: "console_report", key: "console_report_id", collection: "console", entity: ConsoleReport)
resource ConsoleReports {
  @collectionAction("config", operation: "GetConsoleConfig", method: "GET", path: "/console/config", input: {}, authz: public, Gcall: MetadataCollectionRuntime.get_console_config(input) -> console_config, output: console_config)
  @collectionAction("repointel-analytics", operation: "GetRepointelAnalytics", method: "GET", path: "/console/repointel-analytics", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_analytics(input) -> console_report, output: console_report)
  @collectionAction("repointel-author-history", operation: "GetRepointelAuthorHistory", method: "GET", path: "/console/repointel-author-history", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_author_history(input) -> console_report, output: console_report)
  @collectionAction("repointel-ideas-base", operation: "GetRepointelIdeasBase", method: "GET", path: "/console/repointel-ideas-base", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_ideas_base(input) -> console_report, output: console_report)
  @collectionAction("repointel-loci", operation: "GetRepointelLoci", method: "GET", path: "/console/repointel-loci", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_loci(input) -> console_report, output: console_report)
  @collectionAction("repointel-loci-extended", operation: "GetRepointelLociExtended", method: "GET", path: "/console/repointel-loci-extended", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_loci_extended(input) -> console_report, output: console_report)
  @collectionAction("repointel-review-risk", operation: "GetRepointelReviewRisk", method: "GET", path: "/console/repointel-review-risk", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_review_risk(input) -> console_report, output: console_report)
  @collectionAction("repointel-review-risk-messages", operation: "GetRepointelReviewRiskMessages", method: "GET", path: "/console/repointel-review-risk-messages", input: ConsoleReportRequest, authz: reader, Ncall: RepointelAnalyticsProvider.get_review_risk_messages(input) -> console_report, output: console_report)
}

@resource(member: "szz_run", key: "szz_run_id", collection: "szz-runs", entity: SzzRun)
resource SzzRuns {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_szz_runs(input) -> szz_runs, output: szz_runs)
  @get(input: { szz_run_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_szz_run(input) -> szz_run, output: szz_run)
  @delete(input: { szz_run_id: String }, authz: admin, DGcall: MetadataCollectionRuntime.delete_szz_run(input) -> deleted, output: none)
  @collectionAction("search", operation: "SearchSzzAnalyses", method: "POST", path: "/szz-analyses:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_szz_runs(input) -> szz_runs, output: szz_runs)
  @collectionAction("analyze-review", operation: "AnalyzeSzzReview", method: "POST", path: "/szz-analyses:analyze-review", input: SzzAnalysisRequest, authz: writer, DGcall: MetadataCollectionRuntime.prepare_szz_review_analysis(input) -> szz_analysis_request, Ncall: SzzAnalysisProvider.analyze_review(szz_analysis_request) -> szz_provider_run, DGcall: MetadataCollectionRuntime.store_szz_analysis_result(input, szz_provider_run) -> szz_run, output: szz_run)
  @collectionAction("analyze-batch", operation: "AnalyzeSzzBatch", method: "POST", path: "/szz-analyses:analyze-batch", input: SzzAnalysisRequest, authz: writer, DGcall: MetadataCollectionRuntime.prepare_szz_batch_analysis(input) -> szz_analysis_request, Ncall: SzzAnalysisProvider.analyze_batch(szz_analysis_request) -> szz_provider_run, DGcall: MetadataCollectionRuntime.store_szz_analysis_result(input, szz_provider_run) -> szz_run, code: 202, output: szz_run)
}

@resource(member: "downstream_call", key: "downstream_call_id", collection: "downstream-calls", entity: DownstreamCallTrace)
resource DownstreamCalls {
  @list(authz: reader, DGcall: MetadataCollectionRuntime.list_downstream_calls(input) -> downstream_call_traces, output: downstream_call_traces)
  @get(input: { downstream_call_id: String }, authz: reader, DGcall: MetadataCollectionRuntime.get_downstream_call(input) -> downstream_call, output: downstream_call)
  @collectionAction("search", operation: "SearchDownstreamCalls", method: "POST", path: "/downstream-calls:search", input: SearchRequest, authz: reader, DGcall: MetadataCollectionRuntime.search_downstream_calls(input) -> downstream_call_traces, output: downstream_call_traces)
}
