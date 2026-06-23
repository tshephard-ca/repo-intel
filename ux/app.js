const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const repointelCollections = [
  "repository-groups",
  "repositories",
  "sources",
  "normalizers",
  "ingestion-jobs",
  "ingestion-logs",
  "raw-records",
  "authors",
  "arts",
  "metadata",
  "relationships",
];

const metadataCollections = [
  "profiles",
  "scenarios",
  "dictionaries",
  "extractor-bundles",
  "extractor-rules",
  "runs",
  "szz-runs",
  "evidence-hits",
  "coverage-reports",
  "downstream-calls",
];

const ideaSignalLabels = {
  authors: "Authors",
  arts: "Arts",
  bug_nodes: "Bug nodes",
  bug_lifecycle: "Bug lifecycle",
  commit_shas: "Commit SHAs",
  review_votes: "Review votes",
  review_author_links: "Reviewer links",
  commit_bug_links: "Commit-bug links",
  change_commit_links: "Change-commit links",
  change_file_links: "Change-file links",
  change_component_links: "Change-component links",
  security_signals: "Security signals",
  cve_ids: "CVE IDs",
  file_paths: "File paths",
  components: "Components",
  churn: "Churn",
  branches: "Branches",
  ci_messages: "CI messages",
  dependency_paths: "Dependency paths",
  workflow_paths: "Workflow paths",
  repo_settings: "Repo settings",
  release_boundaries: "Release boundaries",
};

const reviewRiskDecisionSignals = [
  { id: "security_sensitivity", label: "Security Sensitivity", weight: 1.0, color: "#087443" },
  { id: "author_competence", label: "Author Competence", weight: 1.3, color: "#b42318" },
  { id: "reviewer_competence", label: "Reviewer Competence", weight: 1.1, color: "#245da8" },
  { id: "review_churn", label: "Review Churn", weight: 0.8, color: "#a56315" },
  { id: "review_friction", label: "Review Friction", weight: 1.0, color: "#c2410c" },
  { id: "review_comment_smell", label: "Review Comment Smell", weight: 1.5, color: "#7a2e0e" },
  { id: "loc_changed", label: "LOC Changed", weight: 0.9, color: "#475467" },
  { id: "file_surface", label: "File Surface", weight: 1.2, color: "#0b7285" },
  { id: "bug_linkage", label: "Bug Linkage", weight: 0.7, color: "#8b4aa9" },
  { id: "bug_comment_smell", label: "Bug Comment Smell", weight: 1.0, color: "#9f1239" },
  { id: "commit_comment_smell", label: "Commit Comment Smell", weight: 0.6, color: "#365314" },
  { id: "staleness", label: "Staleness", weight: 0.3, color: "#667085" },
];

const reviewRiskDecisionSignalMap = new Map(reviewRiskDecisionSignals.map((signal) => [signal.id, signal]));
const reviewRiskShortSignalLabels = {
  security_sensitivity: "Security",
  author_competence: "Author",
  reviewer_competence: "Reviewer",
  review_churn: "Churn",
  review_friction: "Friction",
  review_comment_smell: "Comments",
  loc_changed: "LOC",
  file_surface: "Files",
  bug_linkage: "Bug",
  bug_comment_smell: "Bug Comments",
  commit_comment_smell: "Commit",
  staleness: "Stale",
};

const state = {
  config: {
    repointelProxy: "/api/repointel",
    metadataProxy: "/api/metadata",
    repointelToken: "",
    metadataToken: "",
    analyticsAvailable: false,
    authorDensityMinCommits: 10,
    reviewerDensityMinApprovals: 10,
  },
  data: {},
  selected: {},
  calls: [],
  collapsed: new Set(),
  activeTab: "review-risk",
  jobPollTimer: null,
  lastJobPoll: "",
  lastActiveJobIds: "",
  reviewRiskMessageContext: null,
  reviewRiskRequestId: 0,
  outcomeEvidenceRequestId: 0,
  outcomeEvidence: {
    selectedGroupId: "",
    selectedRunId: "",
    selectedIdentityKey: "",
    rows: [],
  },
  reviewRiskDecision: {
    lastDays: 365,
    limit: 1000,
    mergedOnly: true,
    controls: {},
  },
  repositorySort: {
    field: "group",
    dir: "asc",
  },
  repositoryDetailTab: "repository",
  groupsPage: {
    selectedGroupId: "",
    selectedNode: null,
    syncRun: null,
    pollTimer: null,
    polling: false,
    lastPoll: "",
  },
};

init();

async function init() {
  loadLocalConfig();
  await loadServerConfig();
  bindNavigation();
  bindForms();
  bindActions();
  hydrateConfigInputs();
  renderBrowserCollections();
  await refreshCore();
  activateInitialTab();
}

function bindNavigation() {
  $$(".nav button").forEach((button) => {
    button.addEventListener("click", () => {
      $$(".nav button").forEach((item) => item.classList.remove("active"));
      $$(".tab").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      $(`#${button.dataset.tab}`).classList.add("active");
      state.activeTab = button.dataset.tab;
      if (state.activeTab === "ingestion") {
        refreshIngestion();
        startJobPolling();
      } else if (state.activeTab === "analytics") {
        refreshAnalytics();
        stopJobPolling();
      } else if (state.activeTab === "ideas") {
        refreshIdeasView();
        stopJobPolling();
      } else if (state.activeTab === "review-risk") {
        refreshReviewRisk();
        stopJobPolling();
      } else if (state.activeTab === "outcome-evidence") {
        refreshOutcomeEvidence();
        stopJobPolling();
      } else if (state.activeTab === "groups") {
        refreshGroupsPage();
        stopJobPolling();
      } else if (state.activeTab === "evidence") {
        refreshEvidence();
        stopJobPolling();
      } else {
        stopJobPolling();
      }
    });
  });
  $$(".small-tabs button").forEach((button) => {
    button.addEventListener("click", () => {
      $$(".small-tabs button").forEach((item) => item.classList.remove("active"));
      $$(".edit-form").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      $(`#${button.dataset.form}`).classList.add("active");
    });
  });
}

function activateTab(tabId) {
  const button = $(`.nav button[data-tab="${tabId}"]`);
  if (button) button.click();
}

function activateInitialTab() {
  const tabId = window.location.hash.replace(/^#/, "");
  if (tabId && $(`.nav button[data-tab="${tabId}"]`)) {
    activateTab(tabId);
  }
}

function bindForms() {
  $("#groupForm")?.addEventListener("submit", submitGroup);
  $("#repoForm")?.addEventListener("submit", submitRepo);
  $("#sourceForm")?.addEventListener("submit", submitSource);
  $("#createJobForm")?.addEventListener("submit", submitJob);
  $("#normalizerForm")?.addEventListener("submit", submitNormalizer);
  $("#normalizerTestForm")?.addEventListener("submit", submitNormalizerTest);
  $("#collectionRunForm")?.addEventListener("submit", submitCollectionRun);
  $("#reviewRiskFilters")?.addEventListener("submit", (event) => {
    event.preventDefault();
    refreshReviewRisk();
  });
  $("#outcomeEvidenceFilters")?.addEventListener("submit", (event) => {
    event.preventDefault();
    state.outcomeEvidence.selectedIdentityKey = "";
    refreshOutcomeEvidence();
  });
  $("#browserForm")?.addEventListener("submit", (event) => event.preventDefault());
  $("#browserForm [name='service']")?.addEventListener("change", renderBrowserCollections);
  document.addEventListener("submit", (event) => {
    if (event.target.matches("#groupPageForm")) submitGroupPage(event);
  });
}

function bindActions() {
  $("#saveConfig")?.addEventListener("click", saveConfig);
  $("#healthCheck")?.addEventListener("click", refreshHealth);
  $("#refreshAll")?.addEventListener("click", refreshAll);
  $("#refreshIdeas")?.addEventListener("click", refreshIdeasView);
  $("#refreshReviewRisk")?.addEventListener("click", refreshReviewRisk);
  $("#refreshOutcomeEvidence")?.addEventListener("click", () => refreshOutcomeEvidence({ force: true }));
  $("#refreshAnalytics")?.addEventListener("click", refreshAnalytics);
  $("#applyAuthorDensityThreshold")?.addEventListener("click", applyAuthorDensityThreshold);
  $("#refreshTopology")?.addEventListener("click", refreshTopology);
  $("#refreshGroups")?.addEventListener("click", refreshGroupsPage);
  $("#refreshIngestion")?.addEventListener("click", refreshIngestion);
  $("#refreshNormalizers")?.addEventListener("click", refreshNormalizers);
  $("#refreshCollection")?.addEventListener("click", refreshCollection);
  $("#refreshEvidence")?.addEventListener("click", refreshEvidence);
  $("#retrievalSweep")?.addEventListener("click", retrievalSweep);
  $("#loadSelectedGets")?.addEventListener("click", loadSelectedGets);
  $("#testSelectedSource")?.addEventListener("click", testSelectedSource);
  $("#enqueueSelectedSource")?.addEventListener("click", enqueueSelectedSource);
  $("#planSelectedSource")?.addEventListener("click", planSelectedSource);
  $("#collectSelectedSource")?.addEventListener("click", collectSelectedSource);
  $("#addSwiftSources")?.addEventListener("click", addSwiftSources);
  $("#addRepository")?.addEventListener("click", startRepositoryCreate);
  $("#addGroupFromGroups")?.addEventListener("click", startGroupCreateFromGroups);
  $("#syncSelectedGroup")?.addEventListener("click", startGroupSync);
  $("#startGroupSync")?.addEventListener("click", startGroupSync);
  $("#pauseGroupSync")?.addEventListener("click", pauseGroupSyncAfterCurrentBatch);
  $("#cancelGroupSync")?.addEventListener("click", cancelPendingGroupSync);
  $("#retryFailedGroupSync")?.addEventListener("click", retryFailedGroupSync);
  $("#repoSearch")?.addEventListener("input", renderRepositoryList);
  $("#syncSelectedRepo")?.addEventListener("click", () => syncCurrentRepository());
  $("#addSource")?.addEventListener("click", startSourceCreate);
  $("#cancelSourceEdit")?.addEventListener("click", cancelSourceEdit);
  $("#sourceForm [name='provider']")?.addEventListener("change", syncSourceProviderDefaults);
  $("#deleteSelectedGroup")?.addEventListener("click", () => deleteSelectedResource("group"));
  $("#deleteSelectedRepo")?.addEventListener("click", () => deleteSelectedResource("repo"));
  $("#deleteSelectedSource")?.addEventListener("click", () => deleteSelectedResource("source"));
  $("#newJobForm")?.addEventListener("click", resetJobForm);
  $("#deleteSelectedJob")?.addEventListener("click", deleteSelectedJob);
  $("#loadJobMembers")?.addEventListener("click", loadJobMembers);
  $("#jobMemberLimit")?.addEventListener("change", () => refreshSelectedJobMembers({ resetPaging: true }));
  document.addEventListener("click", (event) => {
    const retryRepo = event.target.closest("[data-group-retry-repo]");
    if (retryRepo) {
      retryGroupRepo(retryRepo.dataset.groupRetryRepo || "");
      return;
    }
    const groupRow = event.target.closest("[data-group-row-id]");
    if (groupRow) {
      selectGroupPageGroup(groupRow.dataset.groupRowId);
      return;
    }
    const groupNode = event.target.closest("[data-group-node-kind]");
    if (groupNode) {
      setGroupSelectedNode(groupNode.dataset.groupNodeKind, groupNode.dataset.groupNodeId || "");
      return;
    }
    const queueRow = event.target.closest("[data-group-queue-repo]");
    if (queueRow) {
      setGroupSelectedNode("queue-repo", queueRow.dataset.groupQueueRepo || "");
      return;
    }
    const deleteGroupButton = event.target.closest("[data-delete-group-page]");
    if (deleteGroupButton) {
      deleteGroupFromGroups();
      return;
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-member-page]");
    if (button) turnJobMemberPage(button.dataset.memberPage, button.dataset.memberDir);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-messages]");
    if (button) {
      openReviewRiskMessages(button.dataset.changeNumber, button.dataset.project, button.dataset.repositoryId);
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-contributors]");
    if (button) {
      openReviewRiskContributors(button.dataset.changeNumber);
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-header]");
    if (button) {
      const meta = reviewRiskColumnMap().get(button.dataset.reviewRiskHeader);
      if (meta) toast(meta.label, false, meta.description);
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-detail-field]");
    if (button) {
      const field = reviewRiskDetailFieldMap().get(button.dataset.reviewRiskDetailField);
      if (field) toast(field.label, false, field.description);
    }
  });
  document.addEventListener("click", (event) => {
    const row = event.target.closest("[data-review-risk-row]");
    if (!row || event.target.closest("a, button, input, select, textarea")) return;
    selectReviewRiskRow(row.dataset.changeNumber);
  });
  document.addEventListener("click", (event) => {
    const row = event.target.closest("[data-outcome-identity-row]");
    if (!row || event.target.closest("a, button, input, select, textarea")) return;
    selectOutcomeIdentity(row.dataset.identityKey || "");
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-outcome-author-history]");
    if (button) openOutcomeAuthorHistory(button.dataset.identityKey || "");
  });
  document.addEventListener("click", (event) => {
    const dot = event.target.closest("[data-review-risk-decision-dot]");
    if (dot) selectReviewRiskRow(dot.dataset.changeNumber);
  });
  document.addEventListener("input", (event) => {
    const limit = event.target.closest("[data-review-risk-limit-slider]");
    if (limit) {
      updateReviewRiskLimitFromInput(limit, { refresh: false });
      return;
    }
    const slider = event.target.closest("[data-review-risk-decision-slider]");
    if (slider) updateReviewRiskDecisionFromInput(slider);
  });
  document.addEventListener("change", (event) => {
    const limit = event.target.closest("[data-review-risk-limit-slider]");
    if (limit) {
      updateReviewRiskLimitFromInput(limit, { refresh: true });
      return;
    }
    const mergedOnly = event.target.closest("[data-review-risk-merged-only]");
    if (mergedOnly) {
      state.reviewRiskDecision.mergedOnly = Boolean(mergedOnly.checked);
      syncReviewRiskFormControls();
      refreshReviewRisk({ clear: true });
      return;
    }
    const outcomeControl = event.target.closest("#outcomeEvidenceFilters select, #outcomeEvidenceFilters input");
    if (outcomeControl) {
      const name = outcomeControl.name || "";
      if (name === "repository_group_id") {
        state.outcomeEvidence.selectedGroupId = outcomeControl.value || "";
        state.outcomeEvidence.selectedRunId = "";
        state.outcomeEvidence.selectedIdentityKey = "";
        refreshOutcomeEvidence({ clear: true });
      } else if (name === "szz_run_id") {
        state.outcomeEvidence.selectedRunId = outcomeControl.value || "";
        state.outcomeEvidence.selectedIdentityKey = "";
        refreshOutcomeEvidence();
      } else {
        state.outcomeEvidence.selectedIdentityKey = "";
        renderOutcomeEvidence();
      }
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-limit-adjust]");
    if (button) adjustReviewRiskLimit(button);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-review-risk-decision-adjust]");
    if (button) adjustReviewRiskDecisionControl(button);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-keyword-adjust]");
    if (button) {
      adjustKeywordWeight(button.dataset.repositoryId || "", button.dataset.keywordId || "", Number(button.dataset.delta || 0));
    }
  });
  $("#closeReviewRiskMessages")?.addEventListener("click", closeReviewRiskMessages);
  $("#reviewRiskMessageModal")?.addEventListener("click", (event) => {
    if (event.target.id === "reviewRiskMessageModal") closeReviewRiskMessages();
  });
  $("#seedProfile")?.addEventListener("click", seedProfile);
  $("#planCollection")?.addEventListener("click", planCollection);
  $("#loadRunEvidence")?.addEventListener("click", loadRunEvidence);
  $("#commitAccepted")?.addEventListener("click", commitAccepted);
  $("#loadRunTraces")?.addEventListener("click", loadRunTraces);
  $("#browserFetch")?.addEventListener("click", browserFetch);
  $("#clearCalls")?.addEventListener("click", () => {
    state.calls = [];
    renderCalls();
  });
  $$("[data-job-action]").forEach((button) => {
    button.addEventListener("click", () => runJobAction(button.dataset.jobAction));
  });
  $$("#repoDetailTabs [data-repo-detail-tab]").forEach((button) => {
    button.addEventListener("click", () => setRepositoryDetailTab(button.dataset.repoDetailTab));
  });
}

async function refreshAll() {
  await refreshHealth();
  await Promise.allSettled([
    refreshTopology(),
    refreshIngestion(),
    refreshNormalizers(),
    refreshCollection(),
    refreshIdeasView({ silent: true }),
  ]);
  renderStats();
  toast("Refreshed console data");
}

async function refreshCore() {
  await Promise.allSettled([
    refreshTopology(),
    refreshIngestion(),
    refreshReviewRisk({ silent: true, clear: true }),
  ]);
}

async function refreshIdeasView(options = {}) {
  setAnalyticsStatuses("Loading", "poll-status active");
  const started = performance.now();
  try {
    const query = new URLSearchParams({
      min_commits: String(authorDensityMinCommits()),
      min_approvals: String(reviewerDensityMinApprovals()),
    });
    const [baseValue, lociValue] = await Promise.all([
      api("metadata", "GET", `/console/repointel-ideas-base?${query.toString()}`),
      api("metadata", "GET", "/console/repointel-loci"),
    ]);
    const lociExtendedValue = await api("metadata", "GET", "/console/repointel-loci-extended");
    state.data.analytics = { ...state.data.analytics, ...baseValue, ...lociValue, ...lociExtendedValue };
    state.data.analyticsError = "";
    renderIdeas();
    setAnalyticsStatuses(`Loaded ${Math.round(performance.now() - started)}ms`, "poll-status");
    if (!options.silent) toast("Ideas refreshed");
  } catch (err) {
    state.data.analyticsError = err.message;
    renderIdeas();
    setAnalyticsStatuses("Analytics unavailable", "poll-status bad");
    if (!options.silent) toast("Ideas unavailable", true, err.message);
  }
}

async function refreshReviewRisk(options = {}) {
  const requestId = (state.reviewRiskRequestId || 0) + 1;
  state.reviewRiskRequestId = requestId;
  const query = reviewRiskQueryString();
  const status = $("#reviewRiskStatus");
  if (!state.config.analyticsAvailable) {
    state.data.reviewRisk = null;
    state.data.reviewRiskError = "Set REPOINTEL_DATABASE_URL on the UX server to enable review risk analytics.";
    renderReviewRisk();
    if (status) {
      status.textContent = "Analytics unavailable";
      status.className = "poll-status bad";
    }
    if (!options.silent) toast("Review risk analytics unavailable", true, state.data.reviewRiskError);
    return;
  }
  if (status) {
    status.textContent = "Loading";
    status.className = "poll-status active";
  }
  if (options.clear) {
    state.data.reviewRisk = null;
    state.data.reviewRiskError = "";
    const cards = $("#reviewRiskCards");
    if (cards) {
      cards.innerHTML = `<div class="stat-card"><div class="value">...</div><div class="label">Loading filtered review risk</div></div>`;
    }
    clearReviewRiskResultViews();
  }
  const started = performance.now();
  try {
    const value = await api("metadata", "GET", `/console/repointel-review-risk${query}`);
    if (requestId !== state.reviewRiskRequestId) return;
    state.data.reviewRisk = value;
    state.data.reviewRiskError = "";
    renderReviewRisk();
    if (status) {
      status.textContent = `Loaded ${Math.round(performance.now() - started)}ms`;
      status.className = "poll-status";
    }
    if (!options.silent) toast("Review risk refreshed");
  } catch (err) {
    if (requestId !== state.reviewRiskRequestId) return;
    state.data.reviewRiskError = err.message;
    renderReviewRisk();
    if (status) {
      status.textContent = "Review risk unavailable";
      status.className = "poll-status bad";
    }
    if (!options.silent) toast("Review risk unavailable", true, err.message);
  }
}

function reviewRiskQueryString() {
  ensureReviewRiskDecisionDefaults();
  const form = $("#reviewRiskFilters");
  if (!form) return "";
  const values = formValue(form);
  const params = new URLSearchParams();
  for (const key of ["repository_id", "project", "month", "date_field"]) {
    const value = String(values[key] ?? "").trim();
    if (value) params.set(key, value);
  }
  const status = state.reviewRiskDecision.mergedOnly ? "MERGED" : String(values.status || "NEW");
  params.set("status", status);
  params.set("limit", String(state.reviewRiskDecision.limit || 1000));
  const query = params.toString();
  return query ? `?${query}` : "";
}

function reviewRiskFilterLabel(filters = {}) {
  const parts = [];
  if (filters.repository_id) parts.push(filters.repository_id);
  if (filters.project) parts.push(filters.project);
  if (filters.status && filters.status !== "ALL") parts.push(filters.status);
  if (filters.month) parts.push(`${filters.date_field || "created"} ${filters.month}`);
  else if (filters.since || filters.until) parts.push(`${filters.date_field || "created"} ${filters.since || "*"}..${filters.until || "*"}`);
  return parts.join(" | ") || "All reviews";
}

async function refreshOutcomeEvidence(options = {}) {
  const requestId = (state.outcomeEvidenceRequestId || 0) + 1;
  state.outcomeEvidenceRequestId = requestId;
  setOutcomeEvidenceStatus("Loading", "poll-status active");
  if (options.clear) clearOutcomeEvidenceViews();
  const started = performance.now();
  try {
    if (!Array.isArray(state.data.groups) || !Array.isArray(state.data.repositories)) {
      await refreshTopology();
    }
    if (options.force || !Array.isArray(state.data.szzRuns)) {
      state.data.szzRuns = outcomeSortRuns(await list("metadata", "/szz-runs"));
    }
    populateOutcomeEvidenceSelectors(state.data.szzRuns || []);
    state.data.outcomeEvidenceError = "";
    const runId = state.outcomeEvidence.selectedRunId || $("#outcomeSzzRun")?.value || "";
    if (!runId) {
      state.data.outcomeEvidenceRun = null;
      renderOutcomeEvidence();
      setOutcomeEvidenceStatus("No group run", "poll-status bad");
      return;
    }
    if (options.force || state.data.outcomeEvidenceRun?.id !== runId) {
      state.data.outcomeEvidenceRun = await api("metadata", "GET", `/szz-runs/${encodeURIComponent(runId)}`);
    }
    if (requestId !== state.outcomeEvidenceRequestId) return;
    state.data.outcomeEvidenceError = "";
    renderOutcomeEvidence();
    setOutcomeEvidenceStatus(`Loaded ${Math.round(performance.now() - started)}ms`, "poll-status");
    if (!options.silent) toast("Outcome evidence refreshed");
  } catch (err) {
    if (requestId !== state.outcomeEvidenceRequestId) return;
    state.data.outcomeEvidenceError = err.message;
    renderOutcomeEvidence();
    setOutcomeEvidenceStatus("Outcome evidence unavailable", "poll-status bad");
    if (!options.silent) toast("Outcome evidence unavailable", true, err.message);
  }
}

function setOutcomeEvidenceStatus(text, className = "poll-status") {
  const status = $("#outcomeEvidenceStatus");
  if (!status) return;
  status.textContent = text;
  status.className = className;
}

function clearOutcomeEvidenceViews() {
  for (const selector of ["#outcomeEvidenceCards", "#outcomeEvidenceContext", "#outcomeIdentityChart", "#outcomeIdentityTable", "#outcomeIdentityDetail", "#outcomeEvidenceMode"]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function populateOutcomeEvidenceSelectors(runs = []) {
  const form = $("#outcomeEvidenceFilters");
  if (!form) return;
  const groupSelect = form.elements.repository_group_id;
  const runSelect = form.elements.szz_run_id;
  const repoSelect = form.elements.repository_id;
  const groups = outcomeRepositoryGroups();
  let groupId = state.outcomeEvidence.selectedGroupId || groupSelect.value || selectedRepository()?.repository_group_id || groups[0]?.id || "";
  if (groupId && !groups.some((group) => group.id === groupId)) groupId = groups[0]?.id || "";
  state.outcomeEvidence.selectedGroupId = groupId;
  if (groupSelect) {
    groupSelect.innerHTML = groups.length
      ? groups.map((group) => `<option value="${escapeAttr(group.id)}">${escapeHtml(groupLabel(group))}</option>`).join("")
      : `<option value="">No repository groups</option>`;
    groupSelect.value = groupId;
  }

  const repos = outcomeReposForGroupId(groupId);
  const currentRepoId = repoSelect?.value || "";
  if (repoSelect) {
    repoSelect.innerHTML = [
      `<option value="">All in group</option>`,
      ...repos.map((repo) => `<option value="${escapeAttr(repo.id)}">${escapeHtml(outcomeRepositoryLabel(repo))}</option>`),
    ].join("");
    repoSelect.value = repos.some((repo) => repo.id === currentRepoId) ? currentRepoId : "";
  }

  const matchingRuns = outcomeRunsForGroup(runs, groupId, repos);
  let runId = state.outcomeEvidence.selectedRunId || runSelect?.value || "";
  if (!matchingRuns.some((run) => run.id === runId)) runId = matchingRuns[0]?.id || "";
  state.outcomeEvidence.selectedRunId = runId;
  if (runSelect) {
    runSelect.innerHTML = matchingRuns.length
      ? matchingRuns.map((run) => `<option value="${escapeAttr(run.id)}">${escapeHtml(outcomeRunLabel(run))}</option>`).join("")
      : `<option value="">No SZZ runs for group</option>`;
    runSelect.value = runId;
  }
}

function outcomeRepositoryGroups() {
  const groups = [...(state.data.groups || [])].sort((a, b) => groupLabel(a).localeCompare(groupLabel(b)));
  if ((state.data.repositories || []).some((repo) => !repo.repository_group_id)) {
    groups.push({ id: "__ungrouped", slug: "ungrouped", name: "Ungrouped", synthetic: true });
  }
  return groups;
}

function outcomeReposForGroupId(groupId) {
  const repos = state.data.repositories || [];
  const filtered = groupId === "__ungrouped"
    ? repos.filter((repo) => !repo.repository_group_id)
    : repos.filter((repo) => repo.repository_group_id === groupId);
  return filtered.sort((a, b) => outcomeRepositoryLabel(a).localeCompare(outcomeRepositoryLabel(b)));
}

function outcomeRunsForGroup(runs, groupId, repos) {
  if (!groupId) return [];
  return outcomeSortRuns(runs).filter((run) => outcomeRunMatchesGroup(run, groupId, repos));
}

function outcomeSortRuns(runs = []) {
  return [...(runs || [])].sort((a, b) => String(outcomeRunTime(b)).localeCompare(String(outcomeRunTime(a))));
}

function outcomeRunMatchesGroup(run, groupId, repos) {
  if (!run || !groupId) return false;
  const selector = run.selector || {};
  if (selector.repository_group_id === groupId) return true;
  if (selector.all) return true;
  const repoIds = new Set(repos.map((repo) => repo.id));
  if (repoIds.has(run.repository_id) || repoIds.has(selector.repository_id)) return true;
  const runKeys = outcomeKeyVariants([run.repository_name, selector.repository_name].filter(Boolean).join(" "));
  if (runKeys.length && repos.some((repo) => outcomeKeysIntersect(runKeys, outcomeRepositoryKeys(repo)))) return true;
  const candidates = outcomeRunCandidates(run);
  return candidates.some((candidate) => outcomeCandidateMatchesGroup(candidate, groupId, repos, run));
}

function outcomeRunLabel(run) {
  const summary = run.summary || {};
  const selector = run.selector || {};
  const scope = selector.repository_group_id || selector.repository_name || run.repository_name || selector.repository_id || run.repository_id || (selector.all ? "all repos" : "selected");
  const count = Number(summary.candidate_rows_kept ?? summary.evidence_hits_count ?? outcomeRunCandidates(run).length ?? 0);
  return `${formatDateTimeCompact(outcomeRunTime(run))} | ${run.status || "run"} | ${scope} | ${formatNumber(count)} candidates`;
}

function outcomeRunTime(run) {
  return run?.generated_at || run?.updated_at || run?.created_at || "";
}

function renderOutcomeEvidence() {
  const cards = $("#outcomeEvidenceCards");
  if (!cards) return;
  if (state.data.outcomeEvidenceError) {
    cards.innerHTML = `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(state.data.outcomeEvidenceError)}</div></div>`;
    clearOutcomeEvidenceResultViews();
    return;
  }
  const values = outcomeEvidenceFormValues();
  const group = outcomeRepositoryGroups().find((item) => item.id === values.groupId);
  const repos = outcomeReposForGroupId(values.groupId);
  const run = state.data.outcomeEvidenceRun;
  if (!group) {
    cards.innerHTML = `<div class="stat-card"><div class="value">-</div><div class="label">Select a repository group</div></div>`;
    clearOutcomeEvidenceResultViews();
    return;
  }
  if (!run) {
    renderOutcomeContext(group, repos, null, values, []);
    cards.innerHTML = `<div class="stat-card"><div class="value">0</div><div class="label">No SZZ run for this repository group</div></div>`;
    clearOutcomeEvidenceResultViews();
    return;
  }

  const candidates = outcomeFilteredCandidates(run, values, repos);
  const aggregate = outcomeAggregateCandidates(candidates, repos, run);
  const rows = outcomeRowsForMode(aggregate, values)
    .filter((row) => row.candidate_rows >= values.minRows)
    .filter((row) => outcomeRowMatchesSearch(row, values.search))
    .sort((a, b) => b.rank_score - a.rank_score || b.candidate_rows - a.candidate_rows || rowDisplayName(a).localeCompare(rowDisplayName(b)));

  if (!rows.some((row) => row.identity_key === state.outcomeEvidence.selectedIdentityKey)) {
    state.outcomeEvidence.selectedIdentityKey = rows[0]?.identity_key || "";
  }
  state.outcomeEvidence.rows = rows;
  renderOutcomeContext(group, repos, run, values, candidates);
  renderOutcomeCards(candidates, aggregate, rows, repos, run);
  renderOutcomeMode(values, rows);
  renderOutcomeChart(rows, values);
  renderOutcomeIdentityTable(rows);
  renderOutcomeIdentityDetail(rows.find((row) => row.identity_key === state.outcomeEvidence.selectedIdentityKey) || rows[0] || null);
}

function clearOutcomeEvidenceResultViews() {
  for (const selector of ["#outcomeIdentityChart", "#outcomeIdentityTable", "#outcomeIdentityDetail", "#outcomeEvidenceMode"]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function outcomeEvidenceFormValues() {
  const form = $("#outcomeEvidenceFilters");
  const values = form ? formValue(form) : {};
  return {
    groupId: values.repository_group_id || state.outcomeEvidence.selectedGroupId || "",
    runId: values.szz_run_id || state.outcomeEvidence.selectedRunId || "",
    repoId: values.repository_id || "",
    role: values.role || "combined",
    evidenceType: values.evidence_type || "all",
    minScore: clampNumber(Number(values.min_score || 0), 0, 100),
    minRows: Math.max(1, Number(values.min_rows || 1)),
    search: String(values.search || "").trim().toLowerCase(),
  };
}

function outcomeFilteredCandidates(run, values, repos) {
  const candidates = outcomeRunCandidates(run);
  const selectedRepo = values.repoId ? repos.find((repo) => repo.id === values.repoId) : null;
  return candidates
    .filter((candidate) => outcomeCandidateMatchesGroup(candidate, values.groupId, repos, run))
    .filter((candidate) => !selectedRepo || outcomeCandidateMatchesRepo(candidate, selectedRepo, run))
    .filter((candidate) => values.evidenceType === "all" || outcomeCandidateType(candidate) === values.evidenceType)
    .filter((candidate) => outcomeCandidateScore(candidate) >= values.minScore);
}

function outcomeRunCandidates(run) {
  const raw = Array.isArray(run?.candidates)
    ? run.candidates
    : Array.isArray(run?.evidence_hits)
      ? run.evidence_hits
      : [];
  return raw.map(outcomeCandidateRecord).filter(Boolean);
}

function outcomeCandidateRecord(item) {
  if (!item || typeof item !== "object") return null;
  if (item.type || item.candidate_commit || item.candidate_review || item.author || item.approvers) return item;
  const value = item.value && typeof item.value === "object"
    ? item.value
    : item.canonical_value && typeof item.canonical_value === "object"
      ? item.canonical_value
      : null;
  return value ? { ...value, __hit: item } : item;
}

function outcomeAggregateCandidates(candidates, repos, run) {
  const aggregate = {
    authors: new Map(),
    approvers: new Map(),
    combined: new Map(),
  };
  for (const candidate of candidates) {
    const repo = outcomeCandidateRepo(candidate, repos, run);
    const score = outcomeCandidateWeightedScore(candidate);
    const author = outcomeCandidateAuthor(candidate);
    if (author) {
      const authorRow = outcomeIdentityRow(aggregate.authors, author, "author");
      outcomeAddCandidateEvidence(authorRow, candidate, repo, "author", score, 1);
      const combinedRow = outcomeIdentityRow(aggregate.combined, author, "combined");
      outcomeAddCandidateEvidence(combinedRow, candidate, repo, "author", score, 1);
    }
    const approvers = outcomeCandidateApprovers(candidate);
    const share = approvers.length ? 1 / approvers.length : 1;
    for (const approver of approvers) {
      const points = score * share;
      const approverRow = outcomeIdentityRow(aggregate.approvers, approver, "approver");
      outcomeAddCandidateEvidence(approverRow, candidate, repo, "approver", points, share);
      const combinedRow = outcomeIdentityRow(aggregate.combined, approver, "combined");
      outcomeAddCandidateEvidence(combinedRow, candidate, repo, "approver", points, share);
    }
  }
  for (const key of ["authors", "approvers", "combined"]) {
    aggregate[key] = new Map(Array.from(aggregate[key], ([identityKey, row]) => [identityKey, outcomeFinalizeIdentityRow(row)]));
  }
  return aggregate;
}

function outcomeIdentityRow(map, actor, role) {
  const identity = outcomeActorIdentity(actor);
  let row = map.get(identity.key);
  if (!row) {
    row = {
      identity_key: identity.key,
      identity,
      role,
      rank_score: 0,
      author_points: 0,
      approver_points: 0,
      candidate_rows: 0,
      direct_rows: 0,
      context_rows: 0,
      lines: 0,
      score_total: 0,
      confidence_total: 0,
      repositories: new Set(),
      repository_ids: new Set(),
      commits: new Set(),
      reviews: new Set(),
      files: new Set(),
      evidence: [],
    };
    map.set(identity.key, row);
  }
  return row;
}

function outcomeAddCandidateEvidence(row, candidate, repo, role, points, share) {
  const type = outcomeCandidateType(candidate);
  const score = outcomeCandidateScore(candidate);
  const confidence = outcomeCandidateConfidence(candidate);
  const lines = Number(candidate.lines || candidate.__hit?.value?.lines || 0);
  const commit = candidate.candidate_commit || candidate.commit_sha || candidate.current_revision || "";
  const review = outcomeCandidateReviewNumber(candidate);
  const repoLabel = repo ? outcomeRepositoryLabel(repo) : outcomeCandidateProject(candidate) || "unknown repo";
  row.rank_score += Number(points || 0);
  if (role === "author") row.author_points += Number(points || 0);
  if (role === "approver") row.approver_points += Number(points || 0);
  row.candidate_rows += 1;
  row.direct_rows += type === "direct" ? 1 : 0;
  row.context_rows += type === "context" ? 1 : 0;
  row.lines += lines * Number(share || 1);
  row.score_total += score;
  row.confidence_total += confidence;
  row.repositories.add(repoLabel);
  if (repo?.id) row.repository_ids.add(repo.id);
  if (commit) row.commits.add(commit);
  if (review) row.reviews.add(review);
  for (const file of outcomeCandidateFiles(candidate)) row.files.add(file);
  row.evidence.push({ candidate, repo, role, points, share, score, confidence, type, lines, commit, review, repoLabel });
}

function outcomeFinalizeIdentityRow(row) {
  const count = Math.max(1, row.candidate_rows || 0);
  return {
    ...row,
    rank_score: roundNumber(row.rank_score, 1),
    author_points: roundNumber(row.author_points, 1),
    approver_points: roundNumber(row.approver_points, 1),
    lines: roundNumber(row.lines, 0),
    avg_score: roundNumber(row.score_total / count, 1),
    avg_confidence: roundNumber(row.confidence_total / count, 2),
    repository_count: row.repositories.size,
    repository_id_count: row.repository_ids.size,
    commit_count: row.commits.size,
    review_count: row.reviews.size,
    file_count: row.files.size,
    repository_labels: Array.from(row.repositories).sort(),
    repository_ids: Array.from(row.repository_ids).sort(),
  };
}

function outcomeRowsForMode(aggregate, values) {
  if (values.role === "authors") return Array.from(aggregate.authors.values());
  if (values.role === "approvers") return Array.from(aggregate.approvers.values());
  return Array.from(aggregate.combined.values());
}

function outcomeRowMatchesSearch(row, search) {
  if (!search) return true;
  const haystack = [
    row.identity_key,
    row.identity.name,
    row.identity.email,
    row.identity.username,
    row.identity.account_id,
    row.identity.author_id,
    ...(row.repository_labels || []),
  ].filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(search);
}

function renderOutcomeContext(group, repos, run, values, candidates) {
  const node = $("#outcomeEvidenceContext");
  if (!node) return;
  const repoChips = repos.map((repo) => {
    const active = !values.repoId || values.repoId === repo.id;
    return `<span class="chip source-chip ${active ? "" : "muted"}">${sourceIconHtml({ type: "commits" }, "source-icon outcome-repo-icon")}${escapeHtml(outcomeRepositoryLabel(repo))}</span>`;
  }).join("");
  node.innerHTML = `
    <div class="outcome-scope-line">
      <span class="outcome-scope-pill">Group</span>
      <strong>${escapeHtml(groupLabel(group))}</strong>
      <span>${escapeHtml(formatNumber(repos.length))} repositories</span>
      <span>${escapeHtml(formatNumber(candidates.length))} scoped candidates</span>
      ${run ? `<span>run ${escapeHtml(run.id || "")}</span>` : ""}
    </div>
    <div class="outcome-repo-chips">${repoChips || `<span class="mini">No repositories in this group.</span>`}</div>
  `;
}

function renderOutcomeCards(candidates, aggregate, rows, repos, run) {
  const cards = $("#outcomeEvidenceCards");
  if (!cards) return;
  const direct = candidates.filter((candidate) => outcomeCandidateType(candidate) === "direct").length;
  const context = candidates.filter((candidate) => outcomeCandidateType(candidate) === "context").length;
  const coveredRepos = new Set(candidates.map((candidate) => outcomeCandidateRepo(candidate, repos, run)?.id || outcomeCandidateProject(candidate)).filter(Boolean));
  const summary = run?.summary || {};
  const reviewCoverage = summary.selected_reviews
    ? `${formatNumber(summary.rows_with_review || 0)} / ${formatNumber(summary.selected_reviews)}`
    : formatNumber(new Set(candidates.map(outcomeCandidateReviewNumber).filter(Boolean)).size);
  cards.innerHTML = [
    ["Candidates", formatNumber(candidates.length)],
    ["Direct", formatNumber(direct)],
    ["Context", formatNumber(context)],
    ["Ranked Authors", formatNumber(aggregate.authors.size)],
    ["Ranked Approvers", formatNumber(aggregate.approvers.size)],
    ["Repositories Covered", `${formatNumber(coveredRepos.size)} / ${formatNumber(repos.length)}`],
    ["Review Coverage", reviewCoverage],
    ["Visible Identities", formatNumber(rows.length)],
  ].map(([label, value]) => statCard(label, value)).join("");
}

function renderOutcomeMode(values, rows) {
  const node = $("#outcomeEvidenceMode");
  if (!node) return;
  const roleLabel = { combined: "Combined", authors: "Authors", approvers: "Approvers" }[values.role] || "Combined";
  const evidenceLabel = { all: "Direct + context", direct: "Direct", context: "Context" }[values.evidenceType] || "Direct + context";
  node.innerHTML = `
    <span class="outcome-mode-pill">${escapeHtml(roleLabel)}</span>
    <span class="outcome-mode-pill">${escapeHtml(evidenceLabel)}</span>
    <span class="outcome-mode-pill">${escapeHtml(formatNumber(rows.length))} identities</span>
  `;
}

function renderOutcomeChart(rows, values) {
  const color = values.role === "authors" ? "#146c63" : values.role === "approvers" ? "#245da8" : "#8b4aa9";
  drawHorizontalBarChart(
    "#outcomeIdentityChart",
    rows.slice(0, 14),
    (row) => rowDisplayName(row),
    (row) => Number(row.rank_score || 0),
    { color },
  );
}

function renderOutcomeIdentityTable(rows) {
  const node = $("#outcomeIdentityTable");
  if (!node) return;
  const selected = state.outcomeEvidence.selectedIdentityKey || rows[0]?.identity_key || "";
  node.innerHTML = `
    <table class="review-risk-compact-table outcome-table">
      <thead>
        <tr>
          <th>Identity</th>
          <th>Rank</th>
          <th>Rows</th>
          <th>Evidence</th>
          <th>Repos</th>
          <th>Commits</th>
          <th>Avg score</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map((row) => `
          <tr
            class="${row.identity_key === selected ? "selected" : ""}"
            data-outcome-identity-row="1"
            data-identity-key="${escapeAttr(row.identity_key)}"
          >
            <td>
              <div class="outcome-identity-cell">
                <strong>${escapeHtml(rowDisplayName(row))}</strong>
                <span>${escapeHtml(row.identity.email || row.identity.username || row.identity_key)}</span>
              </div>
            </td>
            <td>
              <strong>${escapeHtml(formatNumber(row.rank_score || 0))}</strong>
              <div class="mini">${escapeHtml(outcomeRoleMixLabel(row))}</div>
            </td>
            <td>${escapeHtml(formatNumber(row.candidate_rows || 0))}</td>
            <td>
              <span class="outcome-mini-pair"><strong>${escapeHtml(formatNumber(row.direct_rows || 0))}</strong> direct</span>
              <span class="outcome-mini-pair"><strong>${escapeHtml(formatNumber(row.context_rows || 0))}</strong> context</span>
            </td>
            <td>${escapeHtml(formatNumber(row.repository_count || 0))}</td>
            <td>${escapeHtml(formatNumber(row.commit_count || 0))}</td>
            <td>${escapeHtml(formatNumber(row.avg_score || 0))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${rows.length ? "" : `<p class="mini empty-pad">No identities match the current group, run, and filters.</p>`}
  `;
}

function selectOutcomeIdentity(identityKey) {
  if (!identityKey) return;
  state.outcomeEvidence.selectedIdentityKey = identityKey;
  renderOutcomeIdentityTable(state.outcomeEvidence.rows || []);
  const row = (state.outcomeEvidence.rows || []).find((item) => item.identity_key === identityKey) || null;
  renderOutcomeIdentityDetail(row);
}

function renderOutcomeIdentityDetail(row) {
  const node = $("#outcomeIdentityDetail");
  if (!node) return;
  if (!row) {
    node.innerHTML = `<div class="empty">Select an identity row to inspect scoped SZZ evidence.</div>`;
    return;
  }
  const repoRows = outcomeTopGrouped(row.evidence, (item) => item.repoLabel, 8);
  const commitRows = outcomeTopGrouped(row.evidence, (item) => item.commit || "unknown commit", 8);
  const fileRows = outcomeTopFiles(row.evidence, 10);
  node.innerHTML = `
    <div class="outcome-detail-head">
      <div>
        <h4>${escapeHtml(rowDisplayName(row))}</h4>
        <p>${escapeHtml([row.identity.email, row.identity.username, row.identity_key].filter(Boolean).join(" | "))}</p>
      </div>
      <div class="outcome-detail-actions">
        <button type="button" data-outcome-author-history="1" data-identity-key="${escapeAttr(row.identity_key)}">Author History</button>
      </div>
    </div>
    <div class="outcome-detail-grid">
      ${outcomeDetailItem("Rank score", formatNumber(row.rank_score || 0))}
      ${outcomeDetailItem("Author points", formatNumber(row.author_points || 0))}
      ${outcomeDetailItem("Approver points", formatNumber(row.approver_points || 0))}
      ${outcomeDetailItem("Candidate rows", formatNumber(row.candidate_rows || 0))}
      ${outcomeDetailItem("Direct / context", `${formatNumber(row.direct_rows || 0)} / ${formatNumber(row.context_rows || 0)}`)}
      ${outcomeDetailItem("Avg confidence", row.avg_confidence ? formatPercent(row.avg_confidence) : "unknown")}
    </div>
    <div class="outcome-detail-section">
      <h4>Repository Contribution</h4>
      ${outcomeMiniTable(["Repository", "Rows", "Points", "Direct", "Context"], repoRows, (item) => [item.label, item.count, roundNumber(item.points, 1), item.direct, item.context])}
    </div>
    <div class="outcome-detail-section">
      <h4>Top Candidate Commits</h4>
      ${outcomeMiniTable(["Commit", "Rows", "Points", "Review"], commitRows, (item) => [outcomeShortSha(item.label), item.count, roundNumber(item.points, 1), item.review || ""])}
    </div>
    <div class="outcome-detail-section">
      <h4>Top Files</h4>
      ${outcomeMiniTable(["File", "Rows", "Lines"], fileRows, (item) => [item.label, item.count, item.lines])}
    </div>
    <div class="outcome-detail-section">
      <h4>Evidence Snippets</h4>
      <div class="outcome-evidence-snippets">
        ${row.evidence.slice().sort((a, b) => b.points - a.points).slice(0, 8).map(outcomeEvidenceSnippet).join("")}
      </div>
    </div>
  `;
}

function outcomeDetailItem(label, value) {
  return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function outcomeMiniTable(headings, rows, rowFn) {
  if (!rows.length) return `<p class="mini empty-pad">No evidence rows.</p>`;
  return `
    <div class="analytics-table outcome-mini-table">
      <table>
        <thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join("")}</tr></thead>
        <tbody>${rows.map((row) => `<tr>${rowFn(row).map((cell) => `<td>${escapeHtml(formatCell(cell))}</td>`).join("")}</tr>`).join("")}</tbody>
      </table>
    </div>
  `;
}

function outcomeEvidenceSnippet(item) {
  const candidate = item.candidate || {};
  const review = candidate.candidate_review || {};
  const reviewNumber = outcomeCandidateReviewNumber(candidate);
  const reviewLink = review.url
    ? `<a href="${escapeAttr(review.url)}" target="_blank" rel="noreferrer">${escapeHtml(reviewNumber || "review")}</a>`
    : escapeHtml(reviewNumber || "review unknown");
  const fixLink = outcomeFixReviewLink(candidate);
  return `
    <div class="outcome-snippet">
      <div class="outcome-snippet-head">
        <span class="status-pill ${item.type === "direct" ? "good" : "neutral"}">${escapeHtml(item.type)}</span>
        <strong>${escapeHtml(formatNumber(roundNumber(item.points, 1)))} pts</strong>
        <span>${reviewLink}</span>
        ${fixLink}
      </div>
      <p>${escapeHtml(review.subject || candidate.reason || "")}</p>
      <div class="mini">${escapeHtml([item.repoLabel, outcomeShortSha(item.commit), `${formatNumber(item.lines || 0)} lines`, outcomeCandidateFiles(candidate).slice(0, 3).join(", ")].filter(Boolean).join(" | "))}</div>
    </div>
  `;
}

function outcomeFixReviewLink(candidate) {
  const review = candidate.review || candidate.fix_review || candidate.metadata?.fix_review || "";
  const href = candidate.fix_review_url || candidate.metadata?.fix_review_url || candidate.candidate_review?.url || "";
  if (!review || !href) return "";
  return `<a href="${escapeAttr(href)}" target="_blank" rel="noreferrer">fix ${escapeHtml(review)}</a>`;
}

function outcomeTopGrouped(evidence, keyFn, limit) {
  const map = new Map();
  for (const item of evidence || []) {
    const label = keyFn(item) || "unknown";
    const row = map.get(label) || { label, count: 0, points: 0, direct: 0, context: 0, lines: 0, review: "" };
    row.count += 1;
    row.points += Number(item.points || 0);
    row.direct += item.type === "direct" ? 1 : 0;
    row.context += item.type === "context" ? 1 : 0;
    row.lines += Number(item.lines || 0);
    row.review ||= item.review || "";
    map.set(label, row);
  }
  return Array.from(map.values()).sort((a, b) => b.points - a.points || b.count - a.count).slice(0, limit);
}

function outcomeTopFiles(evidence, limit) {
  const map = new Map();
  for (const item of evidence || []) {
    for (const file of outcomeCandidateFiles(item.candidate)) {
      const row = map.get(file) || { label: file, count: 0, lines: 0 };
      row.count += 1;
      row.lines += Number(item.lines || 0);
      map.set(file, row);
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count || b.lines - a.lines).slice(0, limit);
}

async function openOutcomeAuthorHistory(identityKey) {
  const row = (state.outcomeEvidence.rows || []).find((item) => item.identity_key === identityKey);
  if (!row) return toast("Author history unavailable", true, "Identity is not in the current Outcome Evidence table");
  const params = outcomeAuthorHistoryParams(row);
  const modal = $("#reviewRiskMessageModal");
  const title = $("#reviewRiskMessageTitle");
  const subtitle = $("#reviewRiskMessageSubtitle");
  const body = $("#reviewRiskMessageBody");
  if (!modal || !title || !subtitle || !body) return;
  modal.hidden = false;
  title.textContent = `Author History: ${rowDisplayName(row)}`;
  subtitle.textContent = "Loading repository-local author history";
  body.innerHTML = `<div class="json-card">Loading...</div>`;
  try {
    const value = await api("metadata", "GET", `/console/repointel-author-history?${params}`);
    subtitle.textContent = `${rowDisplayName(row)} | ${row.repository_labels.slice(0, 4).join(", ") || "selected group"}`;
    body.innerHTML = renderOutcomeAuthorHistory(value, row);
  } catch (err) {
    subtitle.textContent = "Failed";
    body.innerHTML = `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(err.message)}</div></div>`;
    toast("Author history unavailable", true, err.message);
  }
}

function outcomeAuthorHistoryParams(row) {
  const params = new URLSearchParams({
    include_bugs: "true",
    review_limit: "100",
    commit_limit: "100",
    bug_limit: "50",
  });
  if (row.identity_key.startsWith("gerrit:")) params.set("gerrit_account_id", row.identity_key.replace(/^gerrit:/, ""));
  else if (row.identity_key.startsWith("email:")) params.set("email", row.identity_key.replace(/^email:/, ""));
  else if (row.identity.author_id) params.set("author_id", row.identity.author_id);
  else if (row.identity.email) params.set("email", row.identity.email);
  else if (row.identity.account_id) params.set("gerrit_account_id", row.identity.account_id);
  else params.set("q", rowDisplayName(row));
  if (row.repository_ids.length === 1) params.set("repository_id", row.repository_ids[0]);
  return params.toString();
}

function renderOutcomeAuthorHistory(value, row) {
  const repos = Array.isArray(value.repository_analysis) ? value.repository_analysis : [];
  const cards = [
    ["Repositories", repos.length || row.repository_count || 0],
    ["Reviews", value.reviews_count ?? value.review_count ?? sum(repos, (repo) => Number(repo.reviews_count || repo.review_count || 0))],
    ["Commits", value.commits_count ?? value.commit_count ?? sum(repos, (repo) => Number(repo.commits_count || repo.commit_count || 0))],
    ["SZZ Rows", row.candidate_rows || 0],
  ];
  return `
    <div class="score-breakdown-summary">${cards.map(([label, value]) => statCard(label, formatNumber(value))).join("")}</div>
    ${outcomeMiniTable(
      ["Repository", "Reviews", "Commits", "Risk"],
      repos.slice(0, 12),
      (repo) => [
        repo.repository_name || repo.project || repo.repository_id || "repo",
        repo.reviews_count ?? repo.review_count ?? "",
        repo.commits_count ?? repo.commit_count ?? "",
        repo.risk_score ?? repo.author_history_risk_v1?.risk_score ?? "",
      ],
    )}
    <details class="review-risk-json-detail">
      <summary>Full author history JSON</summary>
      <pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>
    </details>
  `;
}

function outcomeCandidateMatchesGroup(candidate, groupId, repos, run) {
  if (outcomeCandidateRepo(candidate, repos, run)) return true;
  const selector = run?.selector || {};
  return Boolean(groupId && selector.repository_group_id === groupId);
}

function outcomeCandidateMatchesRepo(candidate, repo, run) {
  if (!repo) return false;
  const repoId = outcomeCandidateRepositoryId(candidate);
  if (repoId && outcomeRepositoryIdExists(repoId)) return repoId === repo.id;
  const candidateKeys = outcomeCandidateKeys(candidate, run);
  return outcomeKeysIntersect(candidateKeys, outcomeRepositoryKeys(repo));
}

function outcomeRepositoryIdExists(repoId) {
  return Boolean(repoId && (state.data.repositories || []).some((repo) => repo.id === repoId));
}

function outcomeCandidateRepo(candidate, repos, run) {
  return repos.find((repo) => outcomeCandidateMatchesRepo(candidate, repo, run)) || null;
}

function outcomeCandidateKeys(candidate, run) {
  return outcomeKeyVariants([
    outcomeCandidateRepositoryId(candidate),
    outcomeCandidateProject(candidate),
    candidate.repository_name,
    candidate.__hit?.repository_name,
    run?.repository_name,
    run?.selector?.repository_name,
  ].filter(Boolean).join(" "));
}

function outcomeRepositoryKeys(repo) {
  const sourceKeys = (state.data.sources || [])
    .filter((source) => source.repository_id === repo.id)
    .map((source) => source.external_key || source.name || "");
  return outcomeKeyVariants([repo.id, repo.name, repo.slug, repo.canonical_url, ...sourceKeys].filter(Boolean).join(" "));
}

function outcomeKeysIntersect(left, right) {
  const set = new Set(left);
  return right.some((item) => set.has(item));
}

function outcomeKeyVariants(value) {
  const text = String(value || "").toLowerCase();
  const raw = text.split(/\s+/).filter(Boolean);
  const variants = new Set();
  for (const item of raw) {
    const cleaned = item
      .replace(/^https?:\/\/[^/]+\//, "")
      .replace(/^c\//, "")
      .replace(/\.git$/, "")
      .replace(/[?#].*$/, "")
      .replace(/^\/+|\/+$/g, "");
    if (!cleaned) continue;
    variants.add(cleaned);
    variants.add(cleaned.replace(/^openstack\//, ""));
    variants.add(cleaned.split("/").filter(Boolean).pop() || cleaned);
  }
  return Array.from(variants).filter(Boolean);
}

function outcomeCandidateRepositoryId(candidate) {
  return candidate.repository_id
    || candidate.metadata?.repository_id
    || candidate.__hit?.repository_id
    || candidate.__hit?.proposed_metadata?.[0]?.repository_id
    || "";
}

function outcomeCandidateProject(candidate) {
  return candidate.project
    || candidate.metadata?.project
    || candidate.candidate_review?.project
    || outcomeProjectFromReviewUrl(candidate.candidate_review?.url)
    || "";
}

function outcomeProjectFromReviewUrl(url) {
  const match = String(url || "").match(/\/c\/(.+?)\/\+\//);
  return match ? decodeURIComponent(match[1]) : "";
}

function outcomeCandidateType(candidate) {
  const type = String(candidate.type || candidate.__hit?.key || "").toLowerCase();
  return type.includes("context") ? "context" : "direct";
}

function outcomeCandidateScore(candidate) {
  let score = Number(candidate.score ?? candidate.__hit?.value?.score ?? candidate.__hit?.canonical_value?.score ?? NaN);
  if (!Number.isFinite(score)) score = outcomeCandidateConfidence(candidate) * 100;
  if (score > 0 && score <= 1) score *= 100;
  return clampNumber(score, 0, 100);
}

function outcomeCandidateConfidence(candidate) {
  const raw = candidate.confidence ?? candidate.__hit?.confidence ?? "";
  if (typeof raw === "number") return clampNumber(raw > 1 ? raw / 100 : raw, 0, 1);
  const text = String(raw || "").toLowerCase();
  if (text === "high") return 1;
  if (text === "medium") return 0.7;
  if (text === "low") return 0.45;
  const number = Number(text);
  if (Number.isFinite(number)) return clampNumber(number > 1 ? number / 100 : number, 0, 1);
  return 1;
}

function outcomeCandidateWeightedScore(candidate) {
  const score = outcomeCandidateScore(candidate);
  const confidence = outcomeCandidateConfidence(candidate);
  const typeWeight = outcomeCandidateType(candidate) === "direct" ? 1 : 0.6;
  return score * confidence * typeWeight;
}

function outcomeCandidateAuthor(candidate) {
  if (candidate.author && typeof candidate.author === "object") return candidate.author;
  if (candidate.candidate_author || candidate.candidate_email) {
    return {
      name: candidate.candidate_author || candidate.candidate_email,
      email: candidate.candidate_email || "",
      identity_key: candidate.candidate_email ? `email:${String(candidate.candidate_email).toLowerCase()}` : "",
    };
  }
  return null;
}

function outcomeCandidateApprovers(candidate) {
  const approvers = Array.isArray(candidate.approvers) ? candidate.approvers : Array.isArray(candidate.reviewers) ? candidate.reviewers : [];
  return approvers.filter((item) => item && typeof item === "object");
}

function outcomeActorIdentity(actor = {}) {
  const email = String(actor.email || "").trim();
  const accountId = String(actor.account_id || actor.gerrit_account_id || "").trim();
  const username = String(actor.username || "").trim();
  const authorId = String(actor.author_id || "").trim();
  const name = String(actor.name || actor.display_name || username || email || accountId || authorId || "unknown").trim();
  const key = actor.identity_key
    || (accountId ? `gerrit:${accountId}` : "")
    || (email ? `email:${email.toLowerCase()}` : "")
    || (authorId ? `author:${authorId}` : "")
    || (username ? `username:${username.toLowerCase()}` : "")
    || `name:${name.toLowerCase()}`;
  return {
    key,
    name,
    email,
    username,
    account_id: accountId,
    author_id: authorId,
  };
}

function outcomeCandidateReviewNumber(candidate) {
  return String(candidate.candidate_review?.change_number || candidate.change_number || candidate.review || candidate.fix_review || candidate.metadata?.fix_review || "");
}

function outcomeCandidateFiles(candidate) {
  if (Array.isArray(candidate.files)) return candidate.files.map((item) => String(item || "")).filter(Boolean);
  if (candidate.file) return [String(candidate.file)];
  return [];
}

function rowDisplayName(row) {
  return row?.identity?.name || row?.identity?.email || row?.identity_key || "unknown";
}

function outcomeRoleMixLabel(row) {
  const parts = [];
  if (row.author_points) parts.push(`author ${formatNumber(row.author_points)}`);
  if (row.approver_points) parts.push(`approver ${formatNumber(row.approver_points)}`);
  return parts.join(" | ") || row.role || "";
}

function outcomeRepositoryLabel(repo) {
  return repo?.name || repo?.slug || repo?.id || "unknown";
}

function outcomeShortSha(value) {
  const text = String(value || "");
  return text.length > 12 ? text.slice(0, 12) : text;
}

async function refreshAnalytics(options = {}) {
  setAnalyticsStatuses("Loading", "poll-status active");
  const started = performance.now();
  try {
    const query = new URLSearchParams({
      min_commits: String(authorDensityMinCommits()),
      min_approvals: String(reviewerDensityMinApprovals()),
    });
    const value = await api("metadata", "GET", `/console/repointel-analytics?${query.toString()}`);
    state.data.analytics = { ...state.data.analytics, ...value };
    state.data.analyticsError = "";
    renderAnalytics();
    setAnalyticsStatuses(`Loaded ${Math.round(performance.now() - started)}ms`, "poll-status");
    if (!options.silent) toast("Analytics refreshed");
  } catch (err) {
    state.data.analyticsError = err.message;
    renderAnalytics();
    setAnalyticsStatuses("Analytics unavailable", "poll-status bad");
    if (!options.silent) toast("Analytics unavailable", true, err.message);
  }
}

function applyAuthorDensityThreshold() {
  state.config.authorDensityMinCommits = authorDensityMinCommits();
  state.config.reviewerDensityMinApprovals = reviewerDensityMinApprovals();
  localStorage.setItem("repointel-debug-config", JSON.stringify(state.config));
  refreshAnalytics();
}

function setAnalyticsStatuses(text, className) {
  for (const selector of ["#analyticsStatus", "#ideasStatus"]) {
    const node = $(selector);
    if (!node) continue;
    node.textContent = text;
    node.className = className;
  }
}

async function refreshHealth() {
  const checks = [
    ["Repointel", () => api("repointel", "GET", "/healthz")],
    ["Metadata Collection", () => api("metadata", "GET", "/healthz")],
  ];
  const results = [];
  for (const [label, call] of checks) {
    const started = performance.now();
    try {
      await call();
      results.push({ label, ok: true, ms: performance.now() - started });
    } catch (err) {
      results.push({ label, ok: false, error: err.message, ms: performance.now() - started });
    }
  }
  const panel = $("#healthPanel");
  if (panel) {
    panel.innerHTML = results
      .map(
        (result) => `
          <div class="stat-card ${result.ok ? "good" : "bad"}">
            <div class="value">${result.ok ? "OK" : "ERR"}</div>
            <div class="label">${escapeHtml(result.label)} ${Math.round(result.ms)}ms</div>
            ${result.error ? `<div class="mini">${escapeHtml(result.error)}</div>` : ""}
          </div>
        `,
      )
      .join("");
  } else {
    const okCount = results.filter((result) => result.ok).length;
    toast(`API health ${okCount}/${results.length} OK`, okCount !== results.length);
  }
  return results;
}

async function refreshTopology() {
  const [groups, repositories, sources] = await Promise.all([
    list("repointel", "/repository-groups"),
    list("repointel", "/repositories"),
    list("repointel", "/sources"),
  ]);
  state.data.groups = groups;
  state.data.repositories = repositories;
  state.data.sources = sources;
  if (state.selected.repositoryMode !== "create" && repositories.length && !selectedRepository()) {
    state.selected = { ...state.selected, kind: "repo", id: repositories[0].id, item: repositories[0], repositoryMode: "" };
  }
  ensureGroupsPageSelection();
  renderRepoTree();
  renderGroupsPage();
  renderStats();
}

async function refreshIngestion() {
  const [jobs, logs] = await Promise.all([
    searchList("repointel", "/ingestion-jobs:search", {}, 500),
    list("repointel", "/ingestion-logs"),
  ]);
  state.data.ingestionJobs = jobs;
  state.data.ingestionLogs = logs;
  renderJobs();
  renderSelectedJobPanel();
  renderIngestionBars();
  renderJobPollState();
  renderGroupsPage();
  renderStats();
}

async function refreshNormalizers() {
  state.data.normalizers = await list("repointel", "/normalizers");
  renderNormalizers();
}

async function refreshCollection() {
  const [profiles, scenarios, bundles, rules, runs, hits, traces] = await Promise.all([
    list("metadata", "/profiles"),
    list("metadata", "/scenarios"),
    list("metadata", "/extractor-bundles"),
    list("metadata", "/extractor-rules"),
    list("metadata", "/runs"),
    list("metadata", "/evidence-hits"),
    list("metadata", "/downstream-calls"),
  ]);
  Object.assign(state.data, {
    profiles,
    scenarios,
    bundles,
    rules,
    collectionRuns: runs,
    evidenceHits: hits,
    downstreamCalls: traces,
  });
  renderCollectionRuns();
  renderStats();
}

async function refreshEvidence() {
  const [rawRecords, arts, authors] = await Promise.all([
    list("repointel", "/raw-records"),
    list("repointel", "/arts"),
    list("repointel", "/authors"),
  ]);
  Object.assign(state.data, {
    rawRecords,
    arts,
    authors,
    metadata: state.data.metadata || [],
    relationships: state.data.relationships || [],
    largeEvidenceCollectionsDeferred: true,
  });
  renderEvidence();
  renderRepoTree();
  renderSelectedJobPanel();
  renderStats();
}

function renderStats() {
  const cards = [
    ["Groups", count("groups")],
    ["Repositories", count("repositories")],
    ["Sources", count("sources")],
    ["Jobs", count("ingestionJobs")],
    ["Raw", count("rawRecords")],
    ["Arts", count("arts")],
    ["Authors", count("authors")],
    ["Metadata", count("metadata")],
    ["Relationships", count("relationships")],
    ["Runs", count("collectionRuns")],
    ["Evidence Hits", count("evidenceHits")],
    ["Downstream Calls", count("downstreamCalls")],
  ];
  const statsGrid = $("#statsGrid");
  if (statsGrid) statsGrid.innerHTML = cards.map(([label, value]) => statCard(label, value)).join("");
  const evidenceStats = $("#evidenceStats");
  if (evidenceStats) evidenceStats.innerHTML = cards.slice(4, 9).map(([label, value]) => statCard(label, value)).join("");
}

function renderRepoTree() {
  renderRepositoryGroupOptions();
  renderRepositoryList();
  renderRepositoryDetail();
}

function renderRepositoryGroupOptions() {
  const select = $("#repoGroupSelect");
  if (!select) return;
  const current = select.value || selectedRepository()?.repository_group_id || "";
  const groups = [...(state.data.groups || [])].sort((a, b) => groupLabel(a).localeCompare(groupLabel(b)));
  select.innerHTML = [
    `<option value="">No group</option>`,
    ...groups.map((group) => `<option value="${escapeAttr(group.id)}">${escapeHtml(groupLabel(group))}</option>`),
  ].join("");
  select.value = current;
}

function renderRepositoryList() {
  const node = $("#repoTree");
  if (!node) return;
  const repos = filteredSortedRepositories();
  const selectedRepo = selectedRepository();
  node.innerHTML = `
    <table class="repo-grid-table">
      <thead>
        <tr>
          <th>Group</th>
          <th>Repository</th>
          <th>Sources</th>
          <th>Last sync</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${repos.map((repo) => repositoryTableRow(repo, selectedRepo?.id === repo.id)).join("")}
      </tbody>
    </table>
    ${repos.length ? "" : `<p class="mini empty-pad">No repositories match the filter.</p>`}
  `;
  $$("[data-repo-row-id]", node).forEach((row) => {
    row.addEventListener("click", () => {
      state.repositoryDetailTab = state.repositoryDetailTab || "repository";
      selectResource("repo", row.dataset.repoRowId);
    });
  });
}

function repositoryTableRow(repo, selected) {
  const latest = latestRepositoryJob(repo);
  const status = repositoryStatus(repo);
  return `
    <tr class="${selected ? "selected" : ""}" data-repo-row-id="${escapeAttr(repo.id)}">
      <td>${escapeHtml(groupLabelForRepo(repo))}</td>
      <td>
        <strong>${escapeHtml(repo.name || repo.slug || repo.id)}</strong>
        <div class="mini">${escapeHtml(repo.canonical_url || repo.slug || repo.id)}</div>
      </td>
      <td>${sourceBadgesForRepo(repo.id)}</td>
      <td>${escapeHtml(latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never")}</td>
      <td><span class="status-pill ${escapeAttr(status.tone)}">${escapeHtml(status.label)}</span></td>
    </tr>
  `;
}

function sourceAggregateCount(sourceId, field, fallback = 0) {
  const source = (state.data.analytics?.source_counts || []).find((row) => row.id === sourceId);
  return Number(source?.[field] ?? fallback);
}

function filteredSortedRepositories() {
  const query = String($("#repoSearch")?.value || "").trim().toLowerCase();
  const rows = (state.data.repositories || []).filter((repo) => {
    if (!query) return true;
    return [repo.name, repo.slug, repo.canonical_url, groupLabelForRepo(repo)]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
  return rows.sort((a, b) => {
    const byGroup = groupLabelForRepo(a).localeCompare(groupLabelForRepo(b));
    if (byGroup !== 0) return byGroup;
    return String(a.name || a.slug || a.id).localeCompare(String(b.name || b.slug || b.id));
  });
}

function renderRepositoryDetail() {
  const repo = selectedRepository();
  const creating = state.selected.repositoryMode === "create";
  renderRepositoryDetailHeader(repo, creating);
  renderRepositoryTabs();
  renderRepositoryForm(repo, creating);
  renderRepositorySources(repo);
  renderRepositoryJobs(repo);
}

function renderRepositoryDetailHeader(repo, creating = false) {
  const node = $("#repoDetailHeader");
  if (!node) return;
  if (!repo && !creating) {
    node.innerHTML = `<div><h3>No repository selected</h3><p>Select a repository or add one.</p></div>`;
    return;
  }
  const title = creating ? "New repository" : repo.name || repo.slug || repo.id;
  const status = repo ? repositoryStatus(repo) : { label: "draft", tone: "neutral" };
  node.innerHTML = `
    <div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(creating ? "Configure repository identity before adding sources." : [groupLabelForRepo(repo), repo.canonical_url].filter(Boolean).join(" | "))}</p>
    </div>
    <div class="repo-header-actions">
      <span class="status-pill ${escapeAttr(status.tone)}">${escapeHtml(status.label)}</span>
      <button id="repoHeaderSync" class="primary" ${repo ? "" : "disabled"}>Sync</button>
      <button id="repoHeaderAddSource" ${repo ? "" : "disabled"}>Add Source</button>
      <button id="repoHeaderDelete" class="danger" ${repo ? "" : "disabled"}>Delete</button>
    </div>
  `;
  $("#repoHeaderSync")?.addEventListener("click", () => syncCurrentRepository(repo?.id));
  $("#repoHeaderAddSource")?.addEventListener("click", startSourceCreate);
  $("#repoHeaderDelete")?.addEventListener("click", () => deleteSelectedResource("repo"));
}

function renderRepositoryTabs() {
  $$("#repoDetailTabs [data-repo-detail-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.repoDetailTab === state.repositoryDetailTab);
  });
  $$(".repo-detail-pane").forEach((pane) => pane.classList.remove("active"));
  $(`#repo${capitalize(state.repositoryDetailTab)}Pane`)?.classList.add("active");
}

function renderRepositoryForm(repo, creating = false) {
  const form = $("#repoForm");
  if (!form) return;
  if (repo) {
    form.elements.repository_id.value = repo.id || "";
    form.elements.repository_group_id.value = repo.repository_group_id || "";
    form.elements.slug.value = repo.slug || "";
    form.elements.name.value = repo.name || "";
    form.elements.vcs.value = repo.vcs || "git";
    form.elements.canonical_url.value = repo.canonical_url || "";
    form.elements.default_branch.value = repo.default_branch || "master";
  } else if (creating) {
    form.elements.repository_id.value = "";
    form.elements.repository_group_id.value = form.elements.repository_group_id.value || "";
    form.elements.slug.value = "";
    form.elements.name.value = "";
    form.elements.vcs.value = "git";
    form.elements.canonical_url.value = "";
    form.elements.default_branch.value = "master";
  } else {
    form.elements.repository_id.value = "";
    form.elements.repository_group_id.value = "";
    form.elements.slug.value = "";
    form.elements.name.value = "";
    form.elements.vcs.value = "git";
    form.elements.canonical_url.value = "";
    form.elements.default_branch.value = "master";
  }
  $("#deleteSelectedRepo").disabled = !repo;
}

function renderRepositorySources(repo) {
  const table = $("#repoSourceTable");
  if (!table) return;
  if (!repo) {
    table.innerHTML = `<p class="mini empty-pad">Save the repository before adding sources.</p>`;
    $("#addSource").disabled = true;
    return;
  }
  $("#addSource").disabled = false;
  const sources = sourcesForRepo(repo.id);
  table.innerHTML = `
    <table class="repo-grid-table">
      <thead><tr><th>Type</th><th>Provider</th><th>External key</th><th>Enabled</th><th>Limit</th><th>Last job</th><th>Actions</th></tr></thead>
      <tbody>${sources.map(sourceTableRow).join("")}</tbody>
    </table>
    ${sources.length ? "" : `<p class="mini empty-pad">No sources configured for this repository.</p>`}
  `;
  $$("[data-source-action]", table).forEach((button) => {
    button.addEventListener("click", () => handleRepositorySourceAction(button.dataset.sourceAction, button.dataset.sourceId));
  });
}

function sourceTableRow(source) {
  const latest = latestSourceJob(source.id);
  const policy = source.ingestion_policy || {};
  const limit = policy.review_limit || policy.limit || "";
  return `
    <tr>
      <td>${escapeHtml(source.type || "")}</td>
      <td>${escapeHtml(source.provider || "")}</td>
      <td>${escapeHtml(source.external_key || "")}</td>
      <td>${source.enabled === false ? "no" : "yes"}</td>
      <td>${escapeHtml(limit || "")}</td>
      <td>${escapeHtml(latest ? `${latest.status || "job"} ${formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at)}` : "never")}</td>
      <td class="row-actions">
        <button data-source-action="edit" data-source-id="${escapeAttr(source.id)}">Edit</button>
        <button data-source-action="test" data-source-id="${escapeAttr(source.id)}">Test</button>
        <button data-source-action="ingest" data-source-id="${escapeAttr(source.id)}" class="primary">Ingest</button>
        <button data-source-action="delete" data-source-id="${escapeAttr(source.id)}" class="danger">Delete</button>
      </td>
    </tr>
  `;
}

function renderRepositoryJobs(repo) {
  const table = $("#repoJobsTable");
  if (!table) return;
  if (!repo) {
    table.innerHTML = `<p class="mini empty-pad">Save the repository before viewing jobs.</p>`;
    $("#syncSelectedRepo").disabled = true;
    return;
  }
  $("#syncSelectedRepo").disabled = false;
  const jobs = jobsForRepo(repo.id)
    .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))
    .slice(0, 25);
  table.innerHTML = `
    <table class="repo-grid-table">
      <thead><tr><th>Created</th><th>Source</th><th>Mode</th><th>Status</th><th>Raw</th><th>Arts</th><th>Actions</th></tr></thead>
      <tbody>${jobs.map(repoJobRow).join("")}</tbody>
    </table>
    ${jobs.length ? "" : `<p class="mini empty-pad">No ingestion jobs for this repository.</p>`}
  `;
  $$("[data-open-job]", table).forEach((button) => {
    button.addEventListener("click", () => {
      selectJob(button.dataset.openJob);
      activateTab("ingestion");
      renderJobs();
      renderSelectedJobPanel();
    });
  });
}

function repoJobRow(job) {
  return `
    <tr>
      <td>${escapeHtml(formatDateTimeCompact(job.created_at))}</td>
      <td>${escapeHtml(sourceLabel(jobSourceId(job)))}</td>
      <td>${escapeHtml(job.mode || "")}</td>
      <td><span class="status-pill ${escapeAttr(jobStatusTone(job.status))}">${escapeHtml(job.status || "queued")}</span></td>
      <td>${escapeHtml(formatNumber(job.raw_records_count || 0))}</td>
      <td>${escapeHtml(formatNumber(job.arts_count || 0))}</td>
      <td><button data-open-job="${escapeAttr(job.id)}">Open in Jobs</button></td>
    </tr>
  `;
}

function sourceBadgesForRepo(repoId) {
  const sources = sourcesForRepo(repoId).sort((a, b) => sourceTypeRank(a) - sourceTypeRank(b));
  if (!sources.length) return `<span class="mini">none</span>`;
  return `<div class="source-badges">${sources.map((source) => `<span class="chip source-chip ${source.enabled === false ? "danger" : ""}">${sourceIconHtml(source)}${escapeHtml(sourceBadgeLabel(source))}</span>`).join("")}</div>`;
}

function sourceBadgeLabel(source) {
  if (source.type === "code_reviews") return "reviews";
  if (source.type === "commits") return "git";
  if (source.type === "bugs") return "bugs";
  return source.type || source.provider || "source";
}

function sourceIconType(source) {
  if (source?.type === "code_reviews") return "reviews";
  if (source?.type === "commits") return "git";
  if (source?.type === "bugs") return "bugs";
  return "source";
}

function sourceIconHtml(source, className = "source-icon") {
  const type = sourceIconType(source);
  const paths = {
    git: `<circle cx="6" cy="5" r="2"></circle><circle cx="6" cy="17" r="2"></circle><circle cx="18" cy="11" r="2"></circle><path d="M6 7v8"></path><path d="M8 6c4 0 4 5 8 5"></path>`,
    reviews: `<path d="M5 6h14v9H9l-4 4V6z"></path><path d="M8 9h8"></path><path d="M8 12h5"></path>`,
    bugs: `<path d="M8 8h8v9a4 4 0 0 1-8 0V8z"></path><path d="M9 5h6"></path><path d="M12 5v3"></path><path d="M5 10h3"></path><path d="M16 10h3"></path><path d="M6 17H4"></path><path d="M18 17h2"></path>`,
    source: `<path d="M5 6c0 2 14 2 14 0s-14-2-14 0z"></path><path d="M5 6v10c0 2 14 2 14 0V6"></path><path d="M5 11c0 2 14 2 14 0"></path>`,
  };
  return `<svg class="${escapeAttr(className)} source-icon-${escapeAttr(type)}" viewBox="0 0 24 24" aria-hidden="true">${paths[type] || paths.source}</svg>`;
}

function sourceTypeRank(source) {
  return {
    commits: 1,
    code_reviews: 2,
    bugs: 3,
  }[source.type] || 9;
}

function sourcesForRepo(repoId) {
  return (state.data.sources || []).filter((source) => source.repository_id === repoId);
}

function jobsForRepo(repoId) {
  const sourceIds = new Set(sourcesForRepo(repoId).map((source) => source.id));
  return (state.data.ingestionJobs || []).filter((job) => job.repository_id === repoId || sourceIds.has(jobSourceId(job)));
}

function latestRepositoryJob(repo) {
  return jobsForRepo(repo.id).sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0] || null;
}

function jobSourceId(job) {
  return job.source_id || job.active_source_id || "";
}

function groupLabelForRepo(repo) {
  const group = (state.data.groups || []).find((item) => item.id === repo?.repository_group_id);
  return group ? groupLabel(group) : "Ungrouped";
}

function groupLabel(group) {
  return group.name || group.slug || group.id || "Ungrouped";
}

function repositoryStatus(repo) {
  const sources = sourcesForRepo(repo.id);
  const latest = latestRepositoryJob(repo);
  if (!sources.length) return { label: "missing sources", tone: "bad" };
  if (sources.some((source) => source.enabled === false)) return { label: "disabled source", tone: "warn" };
  if (!sources.some((source) => source.type === "commits")) return { label: "missing git", tone: "bad" };
  if (!sources.some((source) => source.type === "code_reviews")) return { label: "missing reviews", tone: "bad" };
  if (!latest) return { label: "never synced", tone: "warn" };
  if (["failed", "error", "canceled"].includes(String(latest.status || "").toLowerCase())) return { label: "sync failed", tone: "bad" };
  if (["queued", "running"].includes(String(latest.status || "").toLowerCase())) return { label: latest.status, tone: "active" };
  return { label: "healthy", tone: "good" };
}

function jobStatusTone(status) {
  const value = String(status || "").toLowerCase();
  if (["completed", "succeeded", "success"].includes(value)) return "good";
  if (["failed", "error", "canceled"].includes(value)) return "bad";
  if (["queued", "running"].includes(value)) return "active";
  return "neutral";
}

async function refreshGroupsPage() {
  try {
    await refreshTopology();
    await refreshIngestion();
    renderGroupsPage();
  } catch (err) {
    toast("Groups refresh failed", true, err.message);
  }
}

function renderGroupsPage() {
  if (!$("#groupsTable")) return;
  ensureGroupsPageSelection();
  renderGroupsTable();
  renderGroupTreemap();
  renderGroupSyncQueue();
  renderGroupSelectedDetail();
}

function ensureGroupsPageSelection() {
  const groups = groupPageGroups();
  if (!groups.length) {
    state.groupsPage.selectedGroupId = "";
    if (!state.groupsPage.selectedNode) state.groupsPage.selectedNode = null;
    return;
  }
  if (!groups.some((group) => group.id === state.groupsPage.selectedGroupId)) {
    state.groupsPage.selectedGroupId = groups[0].id;
  }
  if (!state.groupsPage.selectedNode) {
    state.groupsPage.selectedNode = { kind: "group", id: state.groupsPage.selectedGroupId };
  }
}

function groupPageGroups() {
  const groups = [...(state.data.groups || [])].sort((a, b) => groupLabel(a).localeCompare(groupLabel(b)));
  const hasUngrouped = (state.data.repositories || []).some((repo) => !repo.repository_group_id);
  if (hasUngrouped) groups.push({ id: "__ungrouped", slug: "ungrouped", name: "Ungrouped", synthetic: true });
  return groups;
}

function selectedGroupPageGroup() {
  return groupPageGroups().find((group) => group.id === state.groupsPage.selectedGroupId) || null;
}

function selectGroupPageGroup(groupId) {
  state.groupsPage.selectedGroupId = groupId;
  state.groupsPage.selectedNode = { kind: "group", id: groupId };
  const group = selectedGroupPageGroup();
  if (group && !group.synthetic) state.selected = { ...state.selected, kind: "group", id: group.id, item: group };
  renderGroupsPage();
}

function setGroupSelectedNode(kind, id) {
  if (kind === "group") return selectGroupPageGroup(id || state.groupsPage.selectedGroupId);
  state.groupsPage.selectedNode = { kind, id };
  if (kind === "repo") {
    const repo = (state.data.repositories || []).find((item) => item.id === id);
    if (repo) state.selected = { ...state.selected, kind: "repo", id: repo.id, item: repo, repositoryMode: "" };
  }
  if (kind === "source") {
    const source = (state.data.sources || []).find((item) => item.id === id);
    if (source) state.selected = { ...state.selected, kind: "source", id: source.id, item: source, repositoryMode: "" };
  }
  renderGroupsPage();
}

function startGroupCreateFromGroups() {
  state.groupsPage.selectedNode = { kind: "group-create", id: "" };
  renderGroupSelectedDetail();
}

function renderGroupsTable() {
  const node = $("#groupsTable");
  if (!node) return;
  const groups = groupPageGroups();
  node.innerHTML = `
    <table class="repo-grid-table group-grid-table">
      <thead>
        <tr>
          <th>Group</th>
          <th>Repos</th>
          <th>Sources</th>
          <th>Last group sync</th>
          <th>Coverage</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>${groups.map(groupTableRow).join("")}</tbody>
    </table>
    ${groups.length ? "" : `<p class="mini empty-pad">No repository groups configured.</p>`}
  `;
}

function groupTableRow(group) {
  const repos = reposForGroupId(group.id);
  const sources = sourcesForGroupId(group.id);
  const coverage = groupCoverage(group.id);
  const status = groupStatus(group.id);
  const latest = groupLatestJob(group.id);
  return `
    <tr class="${group.id === state.groupsPage.selectedGroupId ? "selected" : ""}" data-group-row-id="${escapeAttr(group.id)}">
      <td>
        <strong>${escapeHtml(groupLabel(group))}</strong>
        <div class="mini">${escapeHtml(group.slug || group.id)}</div>
      </td>
      <td>${escapeHtml(formatNumber(repos.length))}</td>
      <td>${escapeHtml(formatNumber(sources.length))}</td>
      <td>${escapeHtml(latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never")}</td>
      <td>${escapeHtml(coverage.label)}</td>
      <td><span class="status-pill ${escapeAttr(status.tone)}">${escapeHtml(status.label)}</span></td>
    </tr>
  `;
}

function reposForGroupId(groupId) {
  const repos = state.data.repositories || [];
  if (groupId === "__ungrouped") return repos.filter((repo) => !repo.repository_group_id);
  return repos.filter((repo) => repo.repository_group_id === groupId);
}

function sourcesForGroupId(groupId) {
  const repoIds = new Set(reposForGroupId(groupId).map((repo) => repo.id));
  return (state.data.sources || []).filter((source) => repoIds.has(source.repository_id));
}

function groupLatestJob(groupId) {
  return reposForGroupId(groupId)
    .flatMap((repo) => jobsForRepo(repo.id))
    .sort((a, b) => dateMillis(b.finished_at || b.updated_at || b.created_at) - dateMillis(a.finished_at || a.updated_at || a.created_at))[0] || null;
}

function groupCoverage(groupId) {
  const repos = reposForGroupId(groupId);
  if (!repos.length) return { ratio: 0, label: "0/0 repos" };
  const complete = repos.filter((repo) => {
    const sourceTypes = new Set(sourcesForRepo(repo.id).filter((source) => source.enabled !== false).map((source) => source.type));
    return sourceTypes.has("commits") && sourceTypes.has("code_reviews") && sourceTypes.has("bugs");
  }).length;
  return { ratio: complete / repos.length, label: `${complete}/${repos.length} repos` };
}

function groupStatus(groupId) {
  const repos = reposForGroupId(groupId);
  if (!repos.length) return { label: "empty", tone: "neutral" };
  const statuses = repos.map(repositoryStatus);
  if (statuses.some((status) => status.tone === "active")) return { label: "syncing", tone: "active" };
  if (statuses.some((status) => status.tone === "bad")) return { label: "needs setup", tone: "bad" };
  if (statuses.some((status) => status.tone === "warn")) return { label: "partial", tone: "warn" };
  return { label: "healthy", tone: "good" };
}

function renderGroupTreemap() {
  const node = $("#groupTreemap");
  if (!node) return;
  renderGroupTreemapLegend();
  const group = selectedGroupPageGroup();
  const title = $("#groupVizTitle");
  const subtitle = $("#groupVizSubtitle");
  if (title) title.textContent = group ? groupLabel(group) : "Group Visualization";
  if (subtitle) {
    const repos = group ? reposForGroupId(group.id) : [];
    const sources = group ? sourcesForGroupId(group.id) : [];
    const latest = group ? groupLatestJob(group.id) : null;
    subtitle.textContent = group
      ? `${formatNumber(repos.length)} repos | ${formatNumber(sources.length)} sources | last sync ${latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never"}`
      : "Repository/source coverage and sync health.";
  }
  node.innerHTML = "";
  if (!group) {
    node.innerHTML = `<p class="mini empty-pad">Add or select a group to visualize repository coverage.</p>`;
    return;
  }
  const data = groupTreemapData(group.id);
  if (!data.children.length) {
    node.innerHTML = `<p class="mini empty-pad">No repositories in this group.</p>`;
    return;
  }
  const d3lib = window.d3;
  if (!d3lib) {
    node.innerHTML = `<p class="mini empty-pad">D3 is not loaded.</p>`;
    return;
  }
  const width = Math.max(720, node.clientWidth || 900);
  const height = Math.max(420, node.clientHeight || 500);
  const root = d3lib.hierarchy(data).sum((item) => Math.max(1, Number(item.value || 0))).sort((a, b) => b.value - a.value);
  d3lib.treemap().size([width, height]).paddingOuter(6).paddingTop(22).paddingInner(3).round(true)(root);
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);

  const repoNodes = root.children || [];
  const repo = svg.selectAll("g.group-treemap-repo").data(repoNodes).join("g").attr("class", "group-treemap-repo");
  repo.append("rect")
    .attr("x", (d) => d.x0)
    .attr("y", (d) => d.y0)
    .attr("width", (d) => Math.max(0, d.x1 - d.x0))
    .attr("height", (d) => Math.max(0, d.y1 - d.y0))
    .attr("fill", "#f8fafc")
    .attr("stroke", (d) => groupSelectedNodeMatches("repo", d.data.id) ? "#146c63" : "#b7c3d3")
    .attr("stroke-width", (d) => groupSelectedNodeMatches("repo", d.data.id) ? 2 : 1)
    .style("cursor", "pointer")
    .on("click", (event, d) => {
      event.stopPropagation();
      setGroupSelectedNode("repo", d.data.id);
    });
  repo.append("text")
    .attr("x", (d) => d.x0 + 6)
    .attr("y", (d) => d.y0 + 15)
    .attr("fill", "#344054")
    .attr("font-size", 11)
    .attr("font-weight", 800)
    .text((d) => fitLabel(d.data.name, Math.max(0, d.x1 - d.x0), 7));

  const leaves = root.leaves();
  const leaf = svg.selectAll("g.group-treemap-leaf").data(leaves).join("g")
    .attr("class", "group-treemap-leaf")
    .attr("transform", (d) => `translate(${d.x0},${d.y0})`)
    .style("cursor", "pointer")
    .on("click", (event, d) => {
      event.stopPropagation();
      if (d.data.kind === "source") setGroupSelectedNode("source", d.data.id);
      else setGroupSelectedNode("repo", d.data.repoId);
    });
  leaf.append("rect")
    .attr("width", (d) => Math.max(0, d.x1 - d.x0))
    .attr("height", (d) => Math.max(0, d.y1 - d.y0))
    .attr("rx", 3)
    .attr("fill", (d) => groupHealthFill(d.data.tone))
    .attr("stroke", (d) => groupSelectedNodeMatches(d.data.kind, d.data.id) ? "#18202b" : groupHealthStroke(d.data.tone))
    .attr("stroke-width", (d) => groupSelectedNodeMatches(d.data.kind, d.data.id) ? 2 : 1);
  const icons = leaf.append("g")
    .attr("class", "group-treemap-icon")
    .attr("transform", (d) => {
      const size = groupTreemapIconSize(d);
      const height = d.y1 - d.y0;
      const x = Math.max(4, ((d.x1 - d.x0) - size) / 2);
      const y = Math.max(4, groupTreemapLeafShowsNumber(d) ? (height - size - 14) / 2 : (height - size) / 2);
      const scale = size / 16;
      return `translate(${x},${y}) scale(${scale})`;
    })
    .style("display", (d) => (groupTreemapLeafIsLarge(d) ? null : "none"));
  icons.each(function(d) {
    const icon = sourceIconSvgSpec(d.data.icon || "source");
    const group = d3lib.select(this);
    for (const path of icon.paths) {
      if (path.tag === "circle") {
        group.append("circle")
          .attr("cx", path.cx)
          .attr("cy", path.cy)
          .attr("r", path.r);
      } else {
        group.append("path").attr("d", path.d);
      }
    }
  });
  leaf.append("text")
    .attr("class", "group-treemap-number")
    .attr("x", (d) => (d.x1 - d.x0) / 2)
    .attr("y", (d) => {
      const size = groupTreemapIconSize(d);
      const height = d.y1 - d.y0;
      const iconY = Math.max(4, (height - size - 14) / 2);
      return Math.min(height - 5, iconY + size + 12);
    })
    .style("display", (d) => (groupTreemapLeafShowsNumber(d) ? null : "none"))
    .text((d) => formatCompactNumber(d.data.rawVolume ?? d.data.value));
  leaf.append("title")
    .text((d) => `${d.parent?.data?.name || ""} ${d.data.name}: ${formatCompactNumber(d.data.rawVolume ?? d.data.value)} ${d.data.statusLabel}`);
}

function renderGroupTreemapLegend() {
  const node = $("#groupTreemapLegend");
  if (!node) return;
  const samples = [
    { type: "commits", label: "git" },
    { type: "code_reviews", label: "reviews" },
    { type: "bugs", label: "bugs" },
  ];
  const health = [
    { tone: "good", label: "fresh" },
    { tone: "active", label: "syncing" },
    { tone: "warn", label: "stale" },
    { tone: "bad", label: "failed" },
    { tone: "neutral", label: "never" },
  ];
  node.innerHTML = `
    <div class="group-legend-items group-source-legend">
      ${samples.map((source) => `<span>${sourceIconHtml(source)}${escapeHtml(source.label)}</span>`).join("")}
    </div>
    <div class="group-legend-items group-health-legend">
      ${health.map((item) => `
        <span><i style="background:${escapeAttr(groupHealthFill(item.tone))};border-color:${escapeAttr(groupHealthStroke(item.tone))}"></i>${escapeHtml(item.label)}</span>
      `).join("")}
    </div>
    <div class="mini">Area uses log-scaled collected volume; large cells show volume, hover shows detail.</div>
  `;
}

function groupTreemapLeafIsLarge(d) {
  return d.x1 - d.x0 >= 34 && d.y1 - d.y0 >= 30;
}

function groupTreemapIconSize(d) {
  const shortest = Math.min(d.x1 - d.x0, d.y1 - d.y0);
  return clampNumber(shortest * 0.42, 14, 30);
}

function groupTreemapLeafShowsNumber(d) {
  return d.x1 - d.x0 >= 78 && d.y1 - d.y0 >= 54;
}

function groupTreemapData(groupId) {
  const group = groupPageGroups().find((item) => item.id === groupId);
  return {
    name: group ? groupLabel(group) : "Group",
    children: reposForGroupId(groupId).map((repo) => {
      const sources = sourcesForRepo(repo.id).sort((a, b) => sourceTypeRank(a) - sourceTypeRank(b));
      return {
        kind: "repo",
        id: repo.id,
        name: repo.name || repo.slug || repo.id,
        children: sources.length
          ? sources.map((source) => {
              const health = sourceHealth(source);
              return {
                kind: "source",
                id: source.id,
                repoId: repo.id,
                name: sourceBadgeLabel(source),
                value: sourceTreemapWeight(source),
                rawVolume: sourceVolume(source),
                icon: sourceIconType(source),
                tone: health.tone,
                statusLabel: health.label,
              };
            })
          : [{
              kind: "missing-source",
              repoId: repo.id,
              name: "missing sources",
              value: 1,
              rawVolume: 0,
              icon: "source",
              tone: "bad",
              statusLabel: "missing",
            }],
      };
    }),
  };
}

function sourceHealth(source) {
  if (!source || source.enabled === false) return { label: "disabled", tone: "bad" };
  const latest = latestSourceJob(source.id);
  if (!latest) return { label: "never", tone: "neutral" };
  const status = String(latest.status || "").toLowerCase();
  if (["failed", "error", "canceled"].includes(status)) return { label: status || "failed", tone: "bad" };
  if (["queued", "running"].includes(status)) return { label: status, tone: "active" };
  const finishedMs = dateMillis(latest.finished_at || latest.updated_at || latest.created_at);
  if (finishedMs && Date.now() - finishedMs > 14 * 24 * 60 * 60 * 1000) return { label: "stale", tone: "warn" };
  return { label: "fresh", tone: "good" };
}

function sourceVolume(source) {
  const counts = sourceCounts(source);
  return Math.max(1, counts.raw + counts.arts + counts.metadata + counts.relationships);
}

function sourceTreemapWeight(source) {
  const volume = sourceVolume(source);
  const floor = source.enabled === false ? 2 : 4;
  return Math.max(floor, Math.log10(volume + 10) * 8);
}

function sourceCounts(source) {
  const latest = latestSourceJob(source.id) || {};
  const raw = Number(latest.raw_records_count ?? sourceAggregateCount(source.id, "raw_records", recordsForSource("rawRecords", source.id).length) ?? 0);
  const arts = Number(latest.arts_count ?? sourceAggregateCount(source.id, "arts", recordsForSource("arts", source.id).length) ?? 0);
  const metadata = Number(latest.metadata_count ?? sourceAggregateCount(source.id, "metadata", recordsForSource("metadata", source.id).length) ?? 0);
  const relationships = Number(latest.relationships_count ?? sourceAggregateCount(source.id, "relationships", recordsForSource("relationships", source.id).length) ?? 0);
  return { raw, arts, metadata, relationships };
}

function groupSelectedNodeMatches(kind, id) {
  const node = state.groupsPage.selectedNode;
  return node?.kind === kind && node.id === id;
}

function groupHealthFill(tone) {
  return {
    good: "#ecfdf3",
    warn: "#fffaeb",
    bad: "#fff1f2",
    active: "#eff6ff",
    neutral: "#f2f4f7",
  }[tone] || "#f2f4f7";
}

function groupHealthStroke(tone) {
  return {
    good: "#9bd7b6",
    warn: "#fedf89",
    bad: "#fecdd3",
    active: "#bfdbfe",
    neutral: "#d0d5dd",
  }[tone] || "#d0d5dd";
}

function sourceIconSvgSpec(type) {
  const specs = {
    git: {
      paths: [
        { tag: "circle", cx: 4, cy: 3, r: 1.7 },
        { tag: "circle", cx: 4, cy: 13, r: 1.7 },
        { tag: "circle", cx: 14, cy: 8, r: 1.7 },
        { tag: "path", d: "M4 5v6" },
        { tag: "path", d: "M5.5 4c3 0 3 4 7 4" },
      ],
    },
    reviews: {
      paths: [
        { tag: "path", d: "M2 3h13v8H6l-4 4V3z" },
        { tag: "path", d: "M5 6h7" },
        { tag: "path", d: "M5 9h4" },
      ],
    },
    bugs: {
      paths: [
        { tag: "path", d: "M5 5h7v8a3.5 3.5 0 0 1-7 0V5z" },
        { tag: "path", d: "M6 2h5" },
        { tag: "path", d: "M8.5 2v3" },
        { tag: "path", d: "M2 7h3" },
        { tag: "path", d: "M12 7h3" },
        { tag: "path", d: "M3 13H1.5" },
        { tag: "path", d: "M14 13h1.5" },
      ],
    },
    source: {
      paths: [
        { tag: "path", d: "M2 4c0 2 13 2 13 0s-13-2-13 0z" },
        { tag: "path", d: "M2 4v8c0 2 13 2 13 0V4" },
        { tag: "path", d: "M2 8c0 2 13 2 13 0" },
      ],
    },
  };
  return specs[type] || specs.source;
}

function renderGroupSyncQueue() {
  const summaryNode = $("#groupSyncSummary");
  const queueNode = $("#groupSyncQueue");
  if (!queueNode) return;
  const run = state.groupsPage.syncRun;
  const groupId = run?.groupId || state.groupsPage.selectedGroupId;
  const group = groupPageGroups().find((item) => item.id === groupId);
  const repos = reposForGroupId(groupId);
  const counts = groupSyncCounts(run, repos);
  const activeRun = run && run.groupId === groupId;
  if (summaryNode) {
    summaryNode.textContent = activeRun
      ? `${groupLabel(group || {})}: ${counts.complete} complete | ${counts.running} running | ${counts.pending} pending | ${counts.failed} failed${state.groupsPage.lastPoll ? ` | ${state.groupsPage.lastPoll}` : ""}`
      : `${group ? groupLabel(group) : "No group"}: ${repos.length} repos | concurrency 3`;
  }
  const syncButton = $("#syncSelectedGroup");
  const startButton = $("#startGroupSync");
  const pauseButton = $("#pauseGroupSync");
  const cancelButton = $("#cancelGroupSync");
  const retryButton = $("#retryFailedGroupSync");
  if (syncButton) syncButton.disabled = !selectedGroupPageGroup() || !reposForGroupId(state.groupsPage.selectedGroupId).length;
  if (startButton) startButton.disabled = !selectedGroupPageGroup() || groupSyncHasActiveDifferentGroup();
  if (pauseButton) pauseButton.disabled = !run || !counts.running;
  if (cancelButton) cancelButton.disabled = !run || !counts.pending;
  if (retryButton) retryButton.disabled = !run || !counts.failed;

  const batches = chunk(repos, 3);
  queueNode.innerHTML = batches.map((batch, index) => `
    <div class="group-sync-batch">
      <div class="group-sync-batch-head">Batch ${index + 1}</div>
      ${batch.map((repo) => groupQueueRow(repo, run)).join("")}
    </div>
  `).join("") || `<p class="mini empty-pad">No repositories in this group.</p>`;
}

function groupQueueRow(repo, run) {
  const tracked = run?.statusByRepo?.[repo.id] || {};
  const job = tracked.jobId ? (state.data.ingestionJobs || []).find((item) => item.id === tracked.jobId) : latestRepositoryJob(repo);
  const status = normalizeGroupJobStatus(tracked.status || job?.status || "ready");
  const counts = groupQueueCounts(tracked, job);
  const elapsed = tracked.startedAt ? elapsedText(tracked.finishedAt || Date.now(), tracked.startedAt) : "";
  return `
    <div class="group-queue-row ${groupSelectedNodeMatches("queue-repo", repo.id) ? "selected" : ""}" data-group-queue-repo="${escapeAttr(repo.id)}">
      <div>
        <strong>${escapeHtml(repo.name || repo.slug || repo.id)}</strong>
        <div class="mini">${escapeHtml(job ? sourceLabel(jobSourceId(job)) : sourceBadgesText(repo.id))}</div>
        ${tracked.error ? `<div class="mini status-bad">${escapeHtml(tracked.error)}</div>` : ""}
      </div>
      <span class="status-pill ${escapeAttr(jobStatusTone(status))}">${escapeHtml(status)}</span>
      <span>${escapeHtml(formatCompactNumber(counts.raw))}</span>
      <span>${escapeHtml(formatCompactNumber(counts.arts))}</span>
      <span>${escapeHtml(formatCompactNumber(counts.metadata))}</span>
      <span>${escapeHtml(elapsed)}</span>
      <button class="mini-action" data-group-retry-repo="${escapeAttr(repo.id)}" ${["failed", "canceled"].includes(status) ? "" : "disabled"}>Retry</button>
    </div>
  `;
}

function sourceBadgesText(repoId) {
  const labels = sourcesForRepo(repoId).sort((a, b) => sourceTypeRank(a) - sourceTypeRank(b)).map(sourceBadgeLabel);
  return labels.length ? labels.join(", ") : "no sources";
}

function groupQueueCounts(tracked = {}, job = {}) {
  const counts = tracked.counts || {};
  return {
    raw: Number(counts.raw ?? job?.raw_records_count ?? 0),
    arts: Number(counts.arts ?? job?.arts_count ?? 0),
    metadata: Number(counts.metadata ?? job?.metadata_count ?? job?.metadata_upserted_count ?? 0),
  };
}

function groupSyncCounts(run, repos = []) {
  const rows = repos.map((repo) => normalizeGroupJobStatus(run?.statusByRepo?.[repo.id]?.status || "ready"));
  return {
    complete: rows.filter((status) => status === "completed").length,
    running: rows.filter(isGroupRepoActiveStatus).length,
    pending: rows.filter((status) => status === "pending" || status === "ready").length,
    failed: rows.filter((status) => status === "failed" || status === "canceled").length,
  };
}

function groupSyncHasActiveDifferentGroup() {
  const run = state.groupsPage.syncRun;
  if (!run || run.groupId === state.groupsPage.selectedGroupId) return false;
  return Object.values(run.statusByRepo || {}).some((row) => isGroupRepoActiveStatus(row.status) || row.status === "pending");
}

async function startGroupSync() {
  const group = selectedGroupPageGroup();
  if (!group) return toast("Select a group first", true);
  if (groupSyncHasActiveDifferentGroup()) return toast("Another group sync is active", true, "Pause, cancel pending, or let it finish before starting another group.");
  const repos = reposForGroupId(group.id);
  if (!repos.length) return toast("Selected group has no repositories", true);
  const current = state.groupsPage.syncRun;
  if (current?.groupId === group.id && groupSyncCounts(current, repos).pending > 0) {
    current.active = true;
    current.pauseAfterCurrent = false;
    current.cancelPending = false;
  } else {
    state.groupsPage.syncRun = {
      groupId: group.id,
      repoIds: repos.map((repo) => repo.id),
      statusByRepo: Object.fromEntries(repos.map((repo) => [repo.id, { status: "pending" }])),
      active: true,
      pauseAfterCurrent: false,
      cancelPending: false,
      startedAt: Date.now(),
      completedAt: null,
    };
  }
  renderGroupsPage();
  await runNextGroupSyncBatch();
}

async function runNextGroupSyncBatch() {
  const run = state.groupsPage.syncRun;
  if (!run?.active) return;
  updateGroupSyncRunFromJobs();
  if (run.cancelPending) {
    markPendingGroupRepos(run, "canceled");
    finishGroupSyncIfIdle();
    renderGroupsPage();
    return;
  }
  const active = run.repoIds.filter((repoId) => isGroupRepoActiveStatus(run.statusByRepo[repoId]?.status));
  if (run.pauseAfterCurrent && !active.length) {
    run.active = false;
    renderGroupsPage();
    stopGroupSyncPollingIfIdle();
    return;
  }
  if (run.pauseAfterCurrent) {
    startGroupSyncPolling();
    renderGroupsPage();
    return;
  }
  const slots = Math.max(0, 3 - active.length);
  const toStart = run.repoIds.filter((repoId) => run.statusByRepo[repoId]?.status === "pending").slice(0, slots);
  if (!toStart.length) {
    finishGroupSyncIfIdle();
    startGroupSyncPolling();
    renderGroupsPage();
    return;
  }
  await Promise.all(toStart.map(enqueueGroupRepoSync));
  finishGroupSyncIfIdle();
  startGroupSyncPolling();
  renderGroupsPage();
}

async function enqueueGroupRepoSync(repoId) {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  const startedAt = Date.now();
  run.statusByRepo[repoId] = { ...(run.statusByRepo[repoId] || {}), status: "queued", startedAt, error: "" };
  renderGroupSyncQueue();
  try {
    const result = await api("repointel", "POST", `/repositories/${repoId}/enqueue-ingestion`, {
      requested_by: "groups-console",
      mode: "repository-sync",
      priority: 10,
      params: {
        sync_current: true,
        git_fetch: true,
        run_sensitivity_scoring: true,
      },
    });
    mergeById("ingestionJobs", [result]);
    run.statusByRepo[repoId] = {
      ...run.statusByRepo[repoId],
      status: normalizeGroupJobStatus(result.status || "queued"),
      jobId: result.id || run.statusByRepo[repoId].jobId || "",
      counts: {
        raw: Number(result.raw_records_count || 0),
        arts: Number(result.arts_count || 0),
        metadata: Number(result.metadata_count || result.metadata_upserted_count || 0),
      },
    };
  } catch (err) {
    run.statusByRepo[repoId] = {
      ...run.statusByRepo[repoId],
      status: "failed",
      error: err.message,
      finishedAt: Date.now(),
    };
  }
}

function startGroupSyncPolling() {
  if (state.groupsPage.pollTimer) return;
  state.groupsPage.pollTimer = window.setInterval(refreshGroupSyncTick, 7000);
}

function stopGroupSyncPollingIfIdle() {
  const run = state.groupsPage.syncRun;
  const hasActive = run && Object.values(run.statusByRepo || {}).some((row) => isGroupRepoActiveStatus(row.status));
  if (!hasActive && state.groupsPage.pollTimer) {
    window.clearInterval(state.groupsPage.pollTimer);
    state.groupsPage.pollTimer = null;
  }
}

async function refreshGroupSyncTick() {
  if (state.groupsPage.polling) return;
  const run = state.groupsPage.syncRun;
  if (!run) return stopGroupSyncPollingIfIdle();
  state.groupsPage.polling = true;
  try {
    state.groupsPage.lastPoll = new Date().toLocaleTimeString();
    await refreshIngestion();
    updateGroupSyncRunFromJobs();
    await refreshTopology();
    updateGroupSyncRunFromJobs();
    await runNextGroupSyncBatch();
    renderGroupsPage();
  } catch (err) {
    toast("Group sync poll failed", true, err.message);
  } finally {
    state.groupsPage.polling = false;
    stopGroupSyncPollingIfIdle();
  }
}

function updateGroupSyncRunFromJobs() {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  for (const repoId of run.repoIds) {
    const tracked = run.statusByRepo[repoId] || { status: "pending" };
    if (!isGroupRepoActiveStatus(tracked.status)) continue;
    const job = tracked.jobId
      ? (state.data.ingestionJobs || []).find((item) => item.id === tracked.jobId)
      : latestRepositoryJob({ id: repoId });
    if (!job) continue;
    const status = normalizeGroupJobStatus(job.status || tracked.status);
    run.statusByRepo[repoId] = {
      ...tracked,
      status,
      jobId: job.id || tracked.jobId || "",
      counts: {
        raw: Number(job.raw_records_count || 0),
        arts: Number(job.arts_count || 0),
        metadata: Number(job.metadata_count || job.metadata_upserted_count || 0),
      },
      finishedAt: isGroupRepoTerminalStatus(status) ? dateMillis(job.finished_at || job.updated_at || job.created_at) || Date.now() : tracked.finishedAt,
    };
  }
  finishGroupSyncIfIdle();
}

function finishGroupSyncIfIdle() {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  const rows = Object.values(run.statusByRepo || {});
  const hasActive = rows.some((row) => isGroupRepoActiveStatus(row.status));
  const hasPending = rows.some((row) => row.status === "pending");
  if (!hasActive && !hasPending) {
    run.active = false;
    run.completedAt = run.completedAt || Date.now();
  }
}

function markPendingGroupRepos(run, status) {
  for (const repoId of run.repoIds) {
    if (run.statusByRepo[repoId]?.status === "pending") {
      run.statusByRepo[repoId] = { ...run.statusByRepo[repoId], status, finishedAt: Date.now() };
    }
  }
}

function pauseGroupSyncAfterCurrentBatch() {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  run.pauseAfterCurrent = true;
  const hasActive = Object.values(run.statusByRepo || {}).some((row) => isGroupRepoActiveStatus(row.status));
  if (!hasActive) run.active = false;
  renderGroupsPage();
  toast("Group sync will pause after current batch");
}

function cancelPendingGroupSync() {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  run.cancelPending = true;
  markPendingGroupRepos(run, "canceled");
  finishGroupSyncIfIdle();
  renderGroupsPage();
  toast("Pending group sync work canceled");
}

async function retryFailedGroupSync() {
  const run = state.groupsPage.syncRun;
  if (!run) return;
  let retryCount = 0;
  for (const repoId of run.repoIds) {
    const status = normalizeGroupJobStatus(run.statusByRepo[repoId]?.status || "");
    if (["failed", "canceled"].includes(status)) {
      retryCount += 1;
      run.statusByRepo[repoId] = { status: "pending" };
    }
  }
  if (!retryCount) return toast("No failed group rows to retry", true);
  run.active = true;
  run.pauseAfterCurrent = false;
  run.cancelPending = false;
  renderGroupsPage();
  await runNextGroupSyncBatch();
}

async function retryGroupRepo(repoId) {
  const run = state.groupsPage.syncRun;
  if (!run?.statusByRepo?.[repoId]) return;
  run.statusByRepo[repoId] = { status: "pending" };
  run.active = true;
  run.pauseAfterCurrent = false;
  run.cancelPending = false;
  renderGroupsPage();
  await runNextGroupSyncBatch();
}

function normalizeGroupJobStatus(status) {
  const value = String(status || "").toLowerCase();
  if (["completed", "succeeded", "success"].includes(value)) return "completed";
  if (["failed", "error"].includes(value)) return "failed";
  if (value === "canceled" || value === "cancelled") return "canceled";
  if (value === "running") return "running";
  if (value === "queued") return "queued";
  if (value === "pending") return "pending";
  if (value === "ready") return "ready";
  return value || "ready";
}

function isGroupRepoActiveStatus(status) {
  return ["queued", "running"].includes(normalizeGroupJobStatus(status));
}

function isGroupRepoTerminalStatus(status) {
  return ["completed", "failed", "canceled"].includes(normalizeGroupJobStatus(status));
}

function renderGroupSelectedDetail() {
  const node = $("#groupSelectedDetail");
  const subtitle = $("#groupSelectedSubtitle");
  if (!node) return;
  const selected = state.groupsPage.selectedNode || { kind: "group", id: state.groupsPage.selectedGroupId };
  if (selected.kind === "group-create") {
    if (subtitle) subtitle.textContent = "Create a repository group.";
    node.innerHTML = groupFormHtml(null);
    return;
  }
  if (selected.kind === "repo" || selected.kind === "queue-repo") {
    const repo = (state.data.repositories || []).find((item) => item.id === selected.id);
    if (subtitle) subtitle.textContent = repo ? repo.name || repo.slug || repo.id : "Repository not found.";
    node.innerHTML = repo ? groupRepoDetailHtml(repo) : `<p class="mini empty-pad">Repository not found.</p>`;
    return;
  }
  if (selected.kind === "source") {
    const source = (state.data.sources || []).find((item) => item.id === selected.id);
    if (subtitle) subtitle.textContent = source ? `${sourceBadgeLabel(source)} source` : "Source not found.";
    node.innerHTML = source ? groupSourceDetailHtml(source) : `<p class="mini empty-pad">Source not found.</p>`;
    return;
  }
  const group = groupPageGroups().find((item) => item.id === (selected.id || state.groupsPage.selectedGroupId));
  if (subtitle) subtitle.textContent = group ? `${groupLabel(group)} metadata, coverage, jobs, and sync state.` : "Select or add a group.";
  node.innerHTML = group ? groupDetailHtml(group) : `<p class="mini empty-pad">No group selected.</p>`;
}

function groupDetailHtml(group) {
  const repos = reposForGroupId(group.id);
  const sources = sourcesForGroupId(group.id);
  const latest = groupLatestJob(group.id);
  const coverage = groupCoverage(group.id);
  const status = groupStatus(group.id);
  return `
    <div class="group-detail-grid">
      <div>
        <div class="quick-stats group-detail-stats">
          <div><strong>${escapeHtml(formatNumber(repos.length))}</strong><span>Repos</span></div>
          <div><strong>${escapeHtml(formatNumber(sources.length))}</strong><span>Sources</span></div>
          <div><strong>${escapeHtml(coverage.label)}</strong><span>Coverage</span></div>
          <div><strong>${escapeHtml(status.label)}</strong><span>Status</span></div>
          <div><strong>${escapeHtml(latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never")}</strong><span>Last sync</span></div>
          <div><strong>${escapeHtml(groupRiskCoverageLabel(group.id))}</strong><span>Risk coverage</span></div>
        </div>
        ${group.synthetic ? `<p class="mini">Synthetic group for repositories without a configured repository group.</p>` : groupFormHtml(group)}
      </div>
      <div class="group-detail-table">${repoCoverageTableHtml(repos)}</div>
      <div class="group-log-tail">${logTailHtml(latest)}</div>
    </div>
  `;
}

function groupRepoDetailHtml(repo) {
  const sources = sourcesForRepo(repo.id).sort((a, b) => sourceTypeRank(a) - sourceTypeRank(b));
  const latest = latestRepositoryJob(repo);
  const status = repositoryStatus(repo);
  const run = state.groupsPage.syncRun;
  const tracked = run?.statusByRepo?.[repo.id];
  return `
    <div class="group-detail-grid">
      <div>
        <div class="quick-stats group-detail-stats">
          <div><strong>${escapeHtml(status.label)}</strong><span>Status</span></div>
          <div><strong>${escapeHtml(formatNumber(sources.length))}</strong><span>Sources</span></div>
          <div><strong>${escapeHtml(latest ? latest.status || "job" : "none")}</strong><span>Latest job</span></div>
          <div><strong>${escapeHtml(latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never")}</strong><span>Last sync</span></div>
          <div><strong>${escapeHtml(tracked ? normalizeGroupJobStatus(tracked.status) : "not queued")}</strong><span>Queue</span></div>
          <div><strong>${escapeHtml(groupRiskCoverageLabel(repo.repository_group_id || "__ungrouped", repo.id))}</strong><span>Risk coverage</span></div>
        </div>
        <div class="group-meta-list">
          <div><span>Repository</span><strong>${escapeHtml(repo.name || repo.slug || repo.id)}</strong></div>
          <div><span>Group</span><strong>${escapeHtml(groupLabelForRepo(repo))}</strong></div>
          <div><span>URL</span><strong>${linkHtml(repo.canonical_url)}</strong></div>
          <div><span>Branch</span><strong>${escapeHtml(repo.default_branch || "unknown")}</strong></div>
        </div>
      </div>
      <div class="group-detail-table">${sourceCoverageTableHtml(sources)}</div>
      <div class="group-log-tail">${logTailHtml(latest)}</div>
    </div>
  `;
}

function groupSourceDetailHtml(source) {
  const repo = (state.data.repositories || []).find((item) => item.id === source.repository_id);
  const latest = latestSourceJob(source.id);
  const health = sourceHealth(source);
  const counts = sourceCounts(source);
  return `
    <div class="group-detail-grid">
      <div>
        <div class="quick-stats group-detail-stats">
          <div><strong>${escapeHtml(health.label)}</strong><span>Health</span></div>
          <div><strong>${escapeHtml(formatCompactNumber(counts.raw))}</strong><span>Raw</span></div>
          <div><strong>${escapeHtml(formatCompactNumber(counts.arts))}</strong><span>Arts</span></div>
          <div><strong>${escapeHtml(formatCompactNumber(counts.metadata))}</strong><span>Metadata</span></div>
          <div><strong>${escapeHtml(formatCompactNumber(counts.relationships))}</strong><span>Relationships</span></div>
          <div><strong>${escapeHtml(latest ? latest.status || "job" : "none")}</strong><span>Latest job</span></div>
        </div>
        <div class="group-meta-list">
          <div><span>Repository</span><strong>${escapeHtml(repo?.name || repo?.slug || source.repository_id || "unknown")}</strong></div>
          <div><span>Source</span><strong>${escapeHtml(source.name || source.id)}</strong></div>
          <div><span>Type</span><strong class="source-inline-label">${sourceIconHtml(source)}${escapeHtml(sourceBadgeLabel(source))}</strong></div>
          <div><span>Provider</span><strong>${escapeHtml(source.provider || "unknown")}</strong></div>
          <div><span>External key</span><strong>${escapeHtml(source.external_key || "")}</strong></div>
          <div><span>Watermark</span><strong>${escapeHtml(sourceWatermark(source))}</strong></div>
        </div>
      </div>
      <div class="group-detail-table">${sourceJobTableHtml(source)}</div>
      <div class="group-log-tail">${logTailHtml(latest)}</div>
    </div>
  `;
}

function groupFormHtml(group) {
  return `
    <form id="groupPageForm" class="repo-form compact-repo-form group-page-form">
      <input name="group_id" type="hidden" value="${escapeAttr(group?.id || "")}" />
      <label>
        <span>Slug</span>
        <input name="slug" value="${escapeAttr(group?.slug || "")}" placeholder="openstack-core" />
      </label>
      <label>
        <span>Name</span>
        <input name="name" value="${escapeAttr(group?.name || "")}" placeholder="OpenStack Core" />
      </label>
      <label class="wide-field">
        <span>Description</span>
        <textarea name="description" placeholder="Repository group purpose">${escapeHtml(group?.description || "")}</textarea>
      </label>
      <div class="form-actions">
        <button type="submit" class="primary">${group ? "Save Group" : "Create Group"}</button>
        <button type="button" data-delete-group-page class="danger" ${group ? "" : "disabled"}>Delete</button>
      </div>
    </form>
  `;
}

function repoCoverageTableHtml(repos) {
  return `
    <table class="repo-grid-table compact-detail-table">
      <thead><tr><th>Repository</th><th>Sources</th><th>Status</th><th>Last sync</th></tr></thead>
      <tbody>${repos.map((repo) => {
        const latest = latestRepositoryJob(repo);
        const status = repositoryStatus(repo);
        return `
          <tr data-group-node-kind="repo" data-group-node-id="${escapeAttr(repo.id)}">
            <td>${escapeHtml(repo.name || repo.slug || repo.id)}</td>
            <td>${escapeHtml(sourceBadgesText(repo.id))}</td>
            <td><span class="status-pill ${escapeAttr(status.tone)}">${escapeHtml(status.label)}</span></td>
            <td>${escapeHtml(latest ? formatDateTimeCompact(latest.finished_at || latest.updated_at || latest.created_at) : "never")}</td>
          </tr>
        `;
      }).join("")}</tbody>
    </table>
  `;
}

function sourceCoverageTableHtml(sources) {
  return `
    <table class="repo-grid-table compact-detail-table">
      <thead><tr><th>Source</th><th>Health</th><th>Raw</th><th>Arts</th><th>Metadata</th><th>Watermark</th></tr></thead>
      <tbody>${sources.map((source) => {
        const health = sourceHealth(source);
        const counts = sourceCounts(source);
        return `
          <tr data-group-node-kind="source" data-group-node-id="${escapeAttr(source.id)}">
            <td><span class="source-inline-label">${sourceIconHtml(source)}${escapeHtml(sourceBadgeLabel(source))}</span></td>
            <td><span class="status-pill ${escapeAttr(health.tone)}">${escapeHtml(health.label)}</span></td>
            <td>${escapeHtml(formatCompactNumber(counts.raw))}</td>
            <td>${escapeHtml(formatCompactNumber(counts.arts))}</td>
            <td>${escapeHtml(formatCompactNumber(counts.metadata))}</td>
            <td>${escapeHtml(sourceWatermark(source))}</td>
          </tr>
        `;
      }).join("")}</tbody>
    </table>
  `;
}

function sourceJobTableHtml(source) {
  const jobs = recordsForSource("ingestionJobs", source.id)
    .sort((a, b) => dateMillis(b.created_at) - dateMillis(a.created_at))
    .slice(0, 8);
  return `
    <table class="repo-grid-table compact-detail-table">
      <thead><tr><th>Job</th><th>Status</th><th>Mode</th><th>Raw</th><th>Arts</th><th>Updated</th></tr></thead>
      <tbody>${jobs.map((job) => `
        <tr>
          <td>${escapeHtml(job.id || "")}</td>
          <td><span class="status-pill ${escapeAttr(jobStatusTone(job.status))}">${escapeHtml(job.status || "queued")}</span></td>
          <td>${escapeHtml(job.mode || "")}</td>
          <td>${escapeHtml(formatCompactNumber(job.raw_records_count || 0))}</td>
          <td>${escapeHtml(formatCompactNumber(job.arts_count || 0))}</td>
          <td>${escapeHtml(formatDateTimeCompact(job.updated_at || job.created_at))}</td>
        </tr>
      `).join("")}</tbody>
    </table>
  `;
}

function logTailHtml(job) {
  if (!job) return `<div><h3>Log Tail</h3><p class="mini">No job selected.</p></div>`;
  const logs = recordsForJob("ingestionLogs", job.id)
    .sort((a, b) => dateMillis(b.created_at) - dateMillis(a.created_at))
    .slice(0, 8);
  return `
    <div>
      <h3>Log Tail</h3>
      ${logs.map((log) => `
        <div class="group-log-row">
          <span>${escapeHtml(formatDateTimeCompact(log.created_at))}</span>
          <strong>${escapeHtml(log.stage || log.level || "log")}</strong>
          <p>${escapeHtml(log.message || "")}</p>
        </div>
      `).join("") || `<p class="mini">No logs loaded for latest job.</p>`}
    </div>
  `;
}

function groupRiskCoverageLabel(groupId, repoId = "") {
  const rows = state.data.reviewRisk?.proposed_review_risk || [];
  if (!rows.length) {
    const sources = repoId ? sourcesForRepo(repoId) : sourcesForGroupId(groupId);
    return sources.some((source) => source.type === "code_reviews") ? "review source" : "missing reviews";
  }
  const repoIds = repoId ? new Set([repoId]) : new Set(reposForGroupId(groupId).map((repo) => repo.id));
  const count = rows.filter((row) => !row.repository_id || repoIds.has(row.repository_id)).length;
  return `${formatNumber(count)} scored`;
}

function sourceWatermark(source) {
  const stateValue = source.ingestion_state || source.state || {};
  return String(source.watermark || source.last_watermark || source.last_seen || stateValue.watermark || stateValue.last_watermark || "none");
}

async function submitGroupPage(event) {
  event.preventDefault();
  const body = compact(formValue(event.currentTarget));
  const groupId = body.group_id;
  delete body.group_id;
  const result = groupId
    ? await api("repointel", "PATCH", `/repository-groups/${encodeURIComponent(groupId)}`, body)
    : await api("repointel", "POST", "/repository-groups", body);
  state.groupsPage.selectedGroupId = result.id;
  state.groupsPage.selectedNode = { kind: "group", id: result.id };
  state.selected = { ...state.selected, kind: "group", id: result.id, item: result };
  await refreshTopology();
  renderGroupsPage();
  toast(groupId ? "Repository group updated" : "Repository group created");
}

async function deleteGroupFromGroups() {
  const group = selectedGroupPageGroup();
  if (!group || group.synthetic) return toast("Select a real group first", true);
  if (!window.confirm(`Delete repository group ${groupLabel(group)}?`)) return;
  await api("repointel", "DELETE", `/repository-groups/${encodeURIComponent(group.id)}`);
  state.groupsPage.selectedGroupId = "";
  state.groupsPage.selectedNode = null;
  await refreshTopology();
  renderGroupsPage();
  toast("Repository group deleted");
}

function chunk(rows, size) {
  const out = [];
  for (let i = 0; i < rows.length; i += size) out.push(rows.slice(i, i + size));
  return out;
}

function fitLabel(label, width, pxPerChar = 7) {
  const max = Math.max(0, Math.floor((width - 12) / pxPerChar));
  const text = String(label || "");
  if (text.length <= max) return text;
  return max > 4 ? `${text.slice(0, max - 3)}...` : "";
}

function dateMillis(value) {
  const text = String(value || "");
  if (!text) return 0;
  const unix = text.match(/^unix:(\d+)$/);
  const date = unix ? new Date(Number(unix[1]) * 1000) : new Date(text);
  const time = date.getTime();
  return Number.isNaN(time) ? 0 : time;
}

function elapsedText(end, start) {
  const ms = Math.max(0, Number(end || Date.now()) - Number(start || Date.now()));
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${rest}s`;
}

function setRepositoryDetailTab(tab) {
  state.repositoryDetailTab = tab || "repository";
  renderRepositoryTabs();
  if (tab === "sources") renderRepositorySources(selectedRepository());
  if (tab === "jobs") renderRepositoryJobs(selectedRepository());
}

function startRepositoryCreate() {
  state.selected = { ...state.selected, kind: "repo", id: "", item: null, repositoryMode: "create" };
  state.repositoryDetailTab = "repository";
  cancelSourceEdit({ render: false });
  renderRepositoryList();
  renderRepositoryDetail();
}

function startSourceCreate() {
  const repo = selectedRepository();
  if (!repo) return toast("Save or select a repository before adding a source", true);
  state.selected = { ...state.selected, kind: "repo", id: repo.id, item: repo, repositoryMode: "" };
  state.repositoryDetailTab = "sources";
  renderRepositoryTabs();
  const form = $("#sourceForm");
  if (!form) return;
  form.hidden = false;
  form.elements.source_id.value = "";
  form.elements.repository_id.value = repo.id;
  const defaults = nextSourceDefaults(repo);
  form.elements.name.value = defaults.name;
  form.elements.type.value = defaults.type;
  form.elements.provider.value = defaults.provider;
  form.elements.base_url.value = defaults.base_url;
  form.elements.external_key.value = defaults.external_key;
  form.elements.local_path.value = defaults.local_path;
  form.elements.limit.value = defaults.limit;
  form.elements.reviews_per_minute.value = defaults.reviews_per_minute;
  form.elements.comments_per_change.value = defaults.comments_per_change;
  form.elements.include_automated_messages.checked = false;
  form.elements.enabled.checked = true;
}

function nextSourceDefaults(repo) {
  const sources = sourcesForRepo(repo.id);
  if (!sources.some((source) => source.type === "commits")) {
    return { name: "Git commits", type: "commits", provider: "git", base_url: repo.canonical_url || "", external_key: repo.slug || repo.name || "", local_path: "", limit: 1000, reviews_per_minute: 6, comments_per_change: 25 };
  }
  if (!sources.some((source) => source.type === "code_reviews")) {
    return { name: "Gerrit reviews", type: "code_reviews", provider: "gerrit", base_url: "", external_key: repo.name || repo.slug || "", local_path: "", limit: 1000, reviews_per_minute: 6, comments_per_change: 25 };
  }
  return { name: "Launchpad bugs", type: "bugs", provider: "launchpad", base_url: "", external_key: repo.slug || repo.name || "", local_path: "", limit: 1000, reviews_per_minute: 6, comments_per_change: 25 };
}

function syncSourceProviderDefaults() {
  const form = $("#sourceForm");
  const repo = selectedRepository();
  if (!form || !repo) return;
  const provider = form.elements.provider.value;
  const defaults = {
    git: { name: "Git commits", type: "commits", base_url: repo.canonical_url || "", external_key: repo.slug || repo.name || "" },
    gerrit: { name: "Gerrit reviews", type: "code_reviews", base_url: "", external_key: repo.name || repo.slug || "" },
    launchpad: { name: "Launchpad bugs", type: "bugs", base_url: "", external_key: repo.slug || repo.name || "" },
    github: { name: "GitHub", type: "commits", base_url: repo.canonical_url || "", external_key: repo.slug || repo.name || "" },
  }[provider];
  if (!defaults) return;
  form.elements.type.value = defaults.type;
  if (!form.elements.name.value || ["Git commits", "Gerrit reviews", "Launchpad bugs", "GitHub"].includes(form.elements.name.value)) {
    form.elements.name.value = defaults.name;
  }
  if (!form.elements.base_url.value) form.elements.base_url.value = defaults.base_url;
  if (!form.elements.external_key.value) form.elements.external_key.value = defaults.external_key;
}

function cancelSourceEdit(options = {}) {
  const form = $("#sourceForm");
  if (form) form.hidden = true;
  if (state.selected.kind === "source") {
    const repo = selectedRepository();
    state.selected = repo ? { ...state.selected, kind: "repo", id: repo.id, item: repo, repositoryMode: "" } : {};
  }
  if (options.render !== false) renderRepositoryDetail();
}

async function handleRepositorySourceAction(action, sourceId) {
  selectResource("source", sourceId);
  if (action === "edit") {
    state.repositoryDetailTab = "sources";
    renderRepositoryDetail();
    return;
  }
  if (action === "test") return await testSelectedSource();
  if (action === "ingest") return await enqueueSelectedSource();
  if (action === "delete") return await deleteSelectedResource("source");
}

function recordsForSource(key, sourceId) {
  if (key === "ingestionJobs") return (state.data.ingestionJobs || []).filter((record) => jobSourceId(record) === sourceId);
  return (state.data[key] || []).filter((record) => record.source_id === sourceId);
}

function recordsForJob(key, jobId) {
  return (state.data[key] || []).filter((record) => record.ingestion_job_id === jobId);
}

function selectedJob() {
  return (state.data.ingestionJobs || []).find((job) => job.id === state.selected.jobId) || null;
}

function sourceLabel(sourceId) {
  if (!sourceId) return "all sources";
  const source = (state.data.sources || []).find((item) => item.id === sourceId);
  if (!source) return sourceId;
  return `${source.name || source.id} (${source.provider || source.type || "source"})`;
}

function activeJobIdSignature() {
  return activeIngestionJobs()
    .map((job) => job.id)
    .sort()
    .join("|");
}

async function repoTreeAction(action, repoId) {
  try {
    selectResource("repo", repoId);
    if (action === "sync-current") return await syncCurrentRepository(repoId);
  } catch (err) {
    toast("Repository action failed", true, err.message);
  }
}

async function sourceTreeAction(action, sourceId) {
  try {
    selectResource("source", sourceId);
    if (action === "ingest") return await enqueueSelectedSource();
    if (action === "test") return await testSelectedSource();
    if (action === "gets") return await loadSelectedGets();
    if (action === "collect") return await collectSelectedSource();
  } catch (err) {
    toast("Source action failed", true, err.message);
  }
}

async function syncCurrentRepository(repoId = selectedRepository()?.id) {
  if (!repoId) return toast("Select a repository first", true);
  toast("Repository sync requested", false, repoId);
  const result = await api("repointel", "POST", `/repositories/${repoId}/enqueue-ingestion`, {
    requested_by: "debug-console",
    mode: "repository-sync",
    priority: 10,
    params: {
      sync_current: true,
      git_fetch: true,
      run_sensitivity_scoring: true,
    },
  });
  selectJob(result.id);
  await refreshIngestion();
  await refreshSelectedJobMembers({ silent: true });
  await refreshEvidence();
  if (state.activeTab === "topology") {
    state.repositoryDetailTab = "jobs";
    renderRepoTree();
  } else {
    activateTab("ingestion");
    startJobPolling();
  }
  $("#memberGets").innerHTML = resultCard("Repository sync enqueued", { ok: true, value: result });
  renderSelectedJobPanel();
  toast("Repository sync enqueued", false, result.id || repoId);
}

function selectResource(kind, id) {
  state.selected = { ...state.selected, kind, id, repositoryMode: "" };
  if (kind === "source") state.repositoryDetailTab = "sources";
  const collection = kind === "group" ? "groups" : kind === "repo" ? "repositories" : "sources";
  const item = (state.data[collection] || []).find((record) => record.id === id);
  state.selected.item = item;
  fillFormsFromSelection(kind, item);
  renderRepoTree();
  const summary = $("#selectedSummary");
  if (summary) summary.innerHTML = selectionSummary(kind, item || {});
}

function fillFormsFromSelection(kind, item = {}) {
  if (kind === "group") {
    $("#groupForm [name='group_id']").value = item.id || "";
    $("#groupForm [name='slug']").value = item.slug || "";
    $("#groupForm [name='name']").value = item.name || "";
    $("#groupForm [name='description']").value = item.description || "";
    $("#repoForm [name='repository_group_id']").value = item.id || "";
  }
  if (kind === "repo") {
    $("#repoForm [name='repository_id']").value = item.id || "";
    $("#repoForm [name='repository_group_id']").value = item.repository_group_id || "";
    $("#repoForm [name='slug']").value = item.slug || "";
    $("#repoForm [name='name']").value = item.name || "";
    $("#repoForm [name='vcs']").value = item.vcs || "git";
    $("#repoForm [name='canonical_url']").value = item.canonical_url || "";
    $("#repoForm [name='default_branch']").value = item.default_branch || "main";
    $("#sourceForm [name='repository_id']").value = item.id || "";
    $("#sourceForm [name='source_id']").value = "";
    $("#sourceForm").hidden = true;
  }
  if (kind === "source") {
    const policy = item.ingestion_policy || {};
    $("#sourceForm").hidden = false;
    $("#sourceForm [name='source_id']").value = item.id || "";
    $("#sourceForm [name='repository_id']").value = item.repository_id || "";
    $("#sourceForm [name='name']").value = item.name || "";
    $("#sourceForm [name='type']").value = item.type || "";
    $("#sourceForm [name='provider']").value = item.provider || "";
    $("#sourceForm [name='base_url']").value = item.base_url || "";
    $("#sourceForm [name='external_key']").value = item.external_key || "";
    $("#sourceForm [name='local_path']").value = policy.local_path || "";
    $("#sourceForm [name='limit']").value = policy.review_limit || policy.limit || "";
    $("#sourceForm [name='reviews_per_minute']").value = policy.reviews_per_minute || "";
    $("#sourceForm [name='comments_per_change']").value = policy.comments_per_change || "";
    $("#sourceForm [name='include_automated_messages']").checked = policy.include_automated_messages === true;
    $("#sourceForm [name='enabled']").checked = item.enabled !== false;
    $("#createJobForm [name='repository_id']").value = item.repository_id || "";
    $("#createJobForm [name='source_id']").value = item.id || "";
    const collectionForm = $("#collectionRunForm");
    if (collectionForm) {
      collectionForm.elements.repository_id.value = item.repository_id || "";
      collectionForm.elements.source_ids.value = item.id || "";
    }
  }
}

async function loadSelectedGets() {
  const selected = state.selected;
  if (!selected.kind || !selected.id) return toast("Select a group, repository, or source first", true);
  const calls = [];
  if (selected.kind === "group") {
    calls.push(["Group", "repointel", `/repository-groups/${selected.id}`]);
    calls.push(["Group Repositories", "repointel", `/repository-groups/${selected.id}/repositories`]);
  }
  if (selected.kind === "repo") {
    calls.push(["Repository", "repointel", `/repositories/${selected.id}`]);
    calls.push(["Repository Sources", "repointel", `/repositories/${selected.id}/sources`]);
  }
  if (selected.kind === "source") {
    for (const suffix of ["", "/ingestion-jobs", "/raw-records", "/arts", "/metadata", "/relationships"]) {
      calls.push([`Source${suffix || ""}`, "repointel", `/sources/${selected.id}${suffix}`]);
    }
  }
  const results = [];
  for (const [label, service, path] of calls) {
    results.push([label, await safeApi(service, "GET", path)]);
  }
  $("#memberGets").innerHTML = results.map(([label, result]) => resultCard(label, result)).join("");
}

async function testSelectedSource() {
  const sources = selectedSources();
  if (!sources.length) return toast("Select a source, repository, or group with sources first", true);
  const results = [];
  for (const source of sources) {
    const result = await api("repointel", "POST", `/sources/${source.id}/test-connection`, { params: {} });
    results.push({ source_id: source.id, name: source.name, result });
  }
  $("#memberGets").innerHTML = resultCard("Source connection tests", { ok: true, value: results });
  toast("Source tests completed", false, `${results.length} source(s)`);
}

async function enqueueSelectedSource() {
  const sources = selectedSources();
  if (!sources.length) return toast("Select a source, repository, or group with sources first", true);
  const mode = $("#createJobForm [name='mode']").value || "incremental";
  toast("Ingest request sent", false, `${sources.length} source(s)`);
  const results = [];
  for (const source of sources) {
    const result = await api("repointel", "POST", `/sources/${source.id}/enqueue-ingestion`, {
      repository_id: source.repository_id,
      requested_by: "debug-console",
      mode,
      priority: 10,
      params: {},
    });
    results.push(result);
  }
  selectJob(results.at(-1)?.id);
  await refreshIngestion();
  await refreshSelectedJobMembers({ silent: true });
  await refreshEvidence();
  if (state.activeTab === "topology") {
    state.repositoryDetailTab = "jobs";
    renderRepoTree();
  } else {
    activateTab("ingestion");
    startJobPolling();
  }
  $("#memberGets").innerHTML = resultCard("Ingestion jobs enqueued", { ok: true, value: { items: results } });
  renderSelectedJobPanel();
  toast("Ingestion enqueued", false, `${results.length} job(s)`);
}

async function planSelectedSource() {
  const sources = selectedSources();
  if (!sources.length) return toast("Select a source, repository, or group with sources first", true);
  await ensureProfileSeeded();
  const result = await api("metadata", "POST", "/runs:plan", selectionCollectionBody(sources, true));
  $("#collectionPlan").textContent = pretty(result);
  $("#memberGets").innerHTML = resultCard("Collection plan", { ok: true, value: result });
  $$(".nav button").find((item) => item.dataset.tab === "collection").click();
  toast("Source collection plan returned");
}

async function collectSelectedSource() {
  const sources = selectedSources();
  if (!sources.length) return toast("Select a source, repository, or group with sources first", true);
  await ensureProfileSeeded();
  const run = await api("metadata", "POST", "/runs", selectionCollectionBody(sources, false));
  state.selected.collectionRunId = run.id;
  const evidence = await api("metadata", "GET", `/runs/${run.id}/evidence-hits`);
  const traces = await api("metadata", "GET", `/runs/${run.id}/downstream-calls`);
  await refreshCollection();
  renderEvidenceHits(items(evidence));
  $("#collectionPlan").textContent = pretty({
    run,
    evidence_count: countItems(evidence),
    downstream_call_count: countItems(traces),
  });
  $$(".nav button").find((item) => item.dataset.tab === "collection").click();
  toast("Source collection run completed");
}

async function addSwiftSources() {
  const repo = selectedRepository() || findSwiftRepository();
  if (!repo) return toast("Select the Swift repository first", true);
  const wanted = [
    {
      name: "Launchpad bugs",
      type: "bugs",
      provider: "launchpad",
      base_url: "https://api.launchpad.net/1.0/swift",
      external_key: "swift",
      enabled: true,
      ingestion_policy: { limit: 1000 },
      ingestion_filters: {},
    },
    {
      name: "Gerrit reviews",
      type: "code_reviews",
      provider: "gerrit",
      base_url: "https://review.opendev.org",
      external_key: "openstack/swift",
      enabled: true,
      ingestion_policy: { review_limit: 1000, limit: 1000, reviews_per_minute: 6, comments_per_change: 25, include_automated_messages: false },
      ingestion_filters: {},
    },
  ];
  const results = [];
  for (const source of wanted) {
    results.push(await ensureSource(repo.id, source));
  }
  await refreshAll();
  selectResource("repo", repo.id);
  $("#memberGets").innerHTML = resultCard("Swift real-data sources", { ok: true, value: { items: results } });
  toast("Swift sources ready", false, results.map((source) => `${source.provider}:${source.id}`).join(" | "));
}

async function ensureSource(repositoryId, source) {
  const search = await api("repointel", "POST", "/sources:search", {
    query: "",
    filters: {
      repository_id: repositoryId,
      provider: source.provider,
      external_key: source.external_key,
    },
    limit: 10,
  });
  const existing = items(search).find(
    (item) =>
      item.repository_id === repositoryId &&
      item.provider === source.provider &&
      item.external_key === source.external_key,
  );
  if (existing) {
    return api("repointel", "PATCH", `/sources/${existing.id}`, {
      repository_id: repositoryId,
      ...source,
    });
  }
  return api("repointel", "POST", "/sources", {
    repository_id: repositoryId,
    ...source,
  });
}

function renderJobs() {
  const jobs = state.data.ingestionJobs || [];
  const sorted = [...jobs].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  $("#jobList").innerHTML = sorted.map((job) => recordCard(job, {
    title: job.id,
    subtitle: `${sourceLabel(job.source_id)} | ${job.mode || ""} | raw=${job.raw_records_count || 0} arts=${job.arts_count || 0} ${jobLogSubtitle(job)}`,
    selected: state.selected.jobId === job.id,
    attrs: `data-job-id="${escapeAttr(job.id)}"`,
  })).join("") || `<p class="mini">No ingestion jobs.</p>`;
  $$("#jobList .record").forEach((item) => {
    item.addEventListener("click", async () => {
      selectJob(item.dataset.jobId);
      renderJobs();
      renderSelectedJobPanel();
      await refreshSelectedJobMembers();
    });
  });
}

function jobLogSubtitle(job) {
  const selectedMembers = state.selected.jobMembers?.jobId === job.id ? state.selected.jobMembers : null;
  if (selectedMembers) return `logs=${pageRangeText("logs", selectedMembers)}`;
  const cachedLogs = recordsForJob("ingestionLogs", job.id).length;
  return cachedLogs ? `logs=${cachedLogs}` : "logs=not loaded";
}

function renderIngestionBars() {
  const node = $("#ingestionBars");
  if (!node) return;
  const jobs = state.data.ingestionJobs || [];
  const groups = groupCounts(jobs, (job) => job.status || "queued");
  const max = Math.max(1, ...Object.values(groups));
  node.innerHTML = Object.entries(groups).map(([label, value]) => barLine(label, value, max)).join("") || `<p class="mini">No jobs.</p>`;
}

function activeIngestionJobs() {
  return (state.data.ingestionJobs || []).filter((job) =>
    ["queued", "running"].includes(String(job.status || "queued").toLowerCase()),
  );
}

function startJobPolling() {
  if (state.jobPollTimer) return;
  state.jobPollTimer = window.setInterval(async () => {
    const beforeActiveIds = activeJobIdSignature();
    if (state.activeTab !== "ingestion" && !beforeActiveIds) {
      stopJobPolling();
      return;
    }
    state.lastJobPoll = new Date().toLocaleTimeString();
    await refreshIngestion();
    if (state.selected.jobId) {
      await refreshSelectedJobMembers({ silent: true });
    }
    const afterActiveIds = activeJobIdSignature();
    if (beforeActiveIds || afterActiveIds || beforeActiveIds !== state.lastActiveJobIds) {
      await refreshEvidence();
    }
    state.lastActiveJobIds = afterActiveIds;
    if (!afterActiveIds && state.activeTab !== "ingestion") {
      stopJobPolling();
    }
  }, 5000);
  renderJobPollState();
}

function stopJobPolling() {
  if (state.jobPollTimer) {
    window.clearInterval(state.jobPollTimer);
    state.jobPollTimer = null;
  }
  renderJobPollState();
}

function renderJobPollState() {
  const node = $("#jobPollStatus");
  if (!node) return;
  const active = activeIngestionJobs();
  if (state.jobPollTimer) {
    node.textContent = `Polling ${active.length} active job(s)${state.lastJobPoll ? ` - ${state.lastJobPoll}` : ""}`;
    node.className = "poll-status active";
  } else {
    node.textContent = active.length ? `${active.length} active job(s)` : "Polling idle";
    node.className = "poll-status";
  }
}

async function loadJobMembers() {
  const jobId = state.selected.jobId;
  if (!jobId) return toast("Select an ingestion job first", true);
  await refreshSelectedJobMembers({ resetPaging: true });
}

async function refreshSelectedJobMembers(options = {}) {
  const jobId = state.selected.jobId;
  if (!jobId) return;
  const job = selectedJob();
  const paging = ensureJobMemberPaging(jobId, options.resetPaging === true);
  const suffixes = ["logs", "raw-records", "arts", "metadata", "relationships"];
  const entries = await Promise.all(
    suffixes.map(async (suffix) => {
      const key = toMemberKey(suffix);
      return [suffix, await safeApi("repointel", "GET", memberPagePath(`/ingestion-jobs/${jobId}/${suffix}`, paging[key]))];
    }),
  );
  const members = { jobId };
  for (const [suffix, result] of entries) {
    members[toMemberKey(suffix)] = result.ok ? items(result.value) : [];
    members[`${toMemberKey(suffix)}Result`] = result;
  }
  if (shouldUseSourceArtifactFallback(job, members)) {
    const [rawRecordsResult, artsResult] = await Promise.all([
      safeApi("repointel", "GET", memberPagePath(`/sources/${job.source_id}/raw-records`, paging.rawRecords)),
      safeApi("repointel", "GET", memberPagePath(`/sources/${job.source_id}/arts`, paging.arts)),
    ]);
    members.rawRecords = rawRecordsResult.ok ? items(rawRecordsResult.value) : members.rawRecords;
    members.arts = artsResult.ok ? items(artsResult.value) : members.arts;
    members.rawRecordsResult = rawRecordsResult;
    members.artsResult = artsResult;
    members.fallback = "source";
  }
  state.selected.jobMembers = members;
  mergeSelectedJobMembersIntoCaches(members);
  renderSelectedJobPanel();
  renderEvidence();
  renderRepoTree();
  if (!options.silent) {
    toast("Job members loaded", false, `logs=${pageRangeText("logs", members)} raw=${pageRangeText("rawRecords", members)} arts=${pageRangeText("arts", members)}`);
  }
}

function selectJob(jobId) {
  if (!jobId) return;
  if (state.selected.jobId !== jobId) {
    state.selected.jobMembers = null;
    resetJobMemberPaging(jobId);
  }
  state.selected.jobId = jobId;
  fillJobForm(selectedJob());
}

function fillJobForm(job) {
  const form = $("#createJobForm");
  if (!form || !job) return;
  form.elements.job_id.value = job.id || "";
  form.elements.repository_id.value = job.repository_id || "";
  form.elements.source_id.value = job.source_id || "";
  form.elements.mode.value = job.mode || "incremental";
  form.elements.status.value = job.status || "";
  form.elements.priority.value = job.priority ?? "";
  form.elements.requested_by.value = job.requested_by || "debug-console";
}

function resetJobForm() {
  const form = $("#createJobForm");
  if (!form) return;
  form.reset();
  form.elements.job_id.value = "";
  form.elements.mode.value = "incremental";
  form.elements.requested_by.value = "debug-console";
  state.selected.jobId = "";
  state.selected.jobMembers = null;
  renderSelectedJobPanel();
  renderJobs();
}

function resetJobMemberPaging(jobId = state.selected.jobId) {
  state.selected.jobMemberPaging = {
    jobId,
    logs: { cursor: "", history: [] },
    rawRecords: { cursor: "", history: [] },
    arts: { cursor: "", history: [] },
    metadata: { cursor: "", history: [] },
    relationships: { cursor: "", history: [] },
  };
}

function ensureJobMemberPaging(jobId = state.selected.jobId, reset = false) {
  if (reset || state.selected.jobMemberPaging?.jobId !== jobId) {
    resetJobMemberPaging(jobId);
  }
  return state.selected.jobMemberPaging;
}

function memberPagePath(basePath, pageState = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(jobMemberLimit()));
  if (pageState.cursor) params.set("cursor", pageState.cursor);
  return `${basePath}?${params.toString()}`;
}

function jobMemberLimit() {
  return Number($("#jobMemberLimit")?.value || 100) || 100;
}

async function turnJobMemberPage(key, direction) {
  const jobId = state.selected.jobId;
  if (!jobId) return toast("Select an ingestion job first", true);
  const paging = ensureJobMemberPaging(jobId);
  const pageState = paging[key];
  if (!pageState) return;
  if (direction === "next") {
    const next = pageCursor(state.selected.jobMembers?.[`${key}Result`]?.value);
    if (!next) return toast("No next page", true);
    pageState.history.push(pageState.cursor || "");
    pageState.cursor = next;
  } else {
    if (!pageState.history.length) return toast("No previous page", true);
    pageState.cursor = pageState.history.pop() || "";
  }
  await refreshSelectedJobMembers({ silent: true });
}

function shouldUseSourceArtifactFallback(job, members) {
  if (!job?.source_id) return false;
  const jobExpectedArtifacts = Number(job.raw_records_count || 0) + Number(job.arts_count || 0);
  const loadedArtifacts = Number(members.rawRecords?.length || 0) + Number(members.arts?.length || 0);
  return jobExpectedArtifacts > 0 && loadedArtifacts === 0;
}

function toMemberKey(suffix) {
  return {
    "logs": "logs",
    "raw-records": "rawRecords",
    "arts": "arts",
    "metadata": "metadata",
    "relationships": "relationships",
  }[suffix];
}

function mergeSelectedJobMembersIntoCaches(members) {
  mergeById("ingestionLogs", members.logs);
  mergeById("rawRecords", members.rawRecords);
  mergeById("arts", members.arts);
  mergeById("metadata", members.metadata);
  mergeById("relationships", members.relationships);
}

function mergeById(key, records = []) {
  if (!records.length) return;
  const byId = new Map((state.data[key] || []).map((record) => [record.id, record]));
  for (const record of records) byId.set(record.id, record);
  state.data[key] = Array.from(byId.values());
}

function renderSelectedJobPanel() {
  const job = selectedJob();
  const members = state.selected.jobMembers?.jobId === state.selected.jobId ? state.selected.jobMembers : null;
  fillJobForm(job);
  const detail = $("#jobDetail");
  if (detail) detail.textContent = pretty(job || {});
  renderJobStats(job, members);
  renderJobMembersDashboard(job, members);
}

function renderJobStats(job, members) {
  const node = $("#jobStats");
  if (!node) return;
  if (!job) {
    node.innerHTML = `<p class="mini">Select or enqueue an ingestion job.</p>`;
    return;
  }
  const stats = [
    ["Status", job.status || "queued"],
    ["Source", sourceLabel(job.source_id)],
    ["Raw", job.raw_records_count || members?.rawRecords?.length || 0],
    ["Arts", job.arts_count || members?.arts?.length || 0],
    ["Authors", job.authors_count || 0],
    ["Logs", members?.logs?.length ?? recordsForJob("ingestionLogs", job.id).length],
    ["Started", job.started_at || ""],
    ["Finished", job.finished_at || ""],
  ];
  node.innerHTML = stats.map(([label, value]) => `
    <div><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>
  `).join("");
}

function renderJobMembersDashboard(job, members) {
  const logsNode = $("#jobLogsList");
  const rawNode = $("#jobRawList");
  const artsNode = $("#jobArtsList");
  const logsPager = $("#jobLogsPager");
  const rawPager = $("#jobRawPager");
  const artsPager = $("#jobArtsPager");
  const jsonNode = $("#jobMembers");
  if (!logsNode || !rawNode || !artsNode || !jsonNode) return;
  const logs = members?.logs || (job ? recordsForJob("ingestionLogs", job.id) : []);
  const rawRecords = members?.rawRecords || (job ? recordsForJob("rawRecords", job.id) : []);
  const arts = sortReviewArts(members?.arts || (job ? recordsForJob("arts", job.id) : []));
  const displayed = { logs, rawRecords, arts };
  if (logsPager) logsPager.innerHTML = memberPagerHtml("logs", members);
  if (rawPager) rawPager.innerHTML = memberPagerHtml("rawRecords", members);
  if (artsPager) artsPager.innerHTML = memberPagerHtml("arts", members);
  const fallbackNotice = members?.fallback === "source"
    ? `<div class="member-notice">This job's deduped artifacts are currently attached to the source/latest upserted records, so the panels show source artifacts for ${escapeHtml(sourceLabel(job?.source_id))}.</div>`
    : "";
  logsNode.innerHTML = logs.map((log, index) => `
    <div class="record compact-record" data-job-member="logs" data-index="${index}">
      <div class="record-title">
        <span>${escapeHtml(log.stage || "log")}</span>
        <span class="chip">${escapeHtml(log.level || "")}</span>
      </div>
      <div class="record-body">${escapeHtml(log.created_at || "")}<br />${escapeHtml(log.message || "")}</div>
    </div>
  `).join("") || `<p class="mini">No logs loaded.</p>`;
  rawNode.innerHTML = `${fallbackNotice}${rawRecords.map((record, index) => `
    <div class="record compact-record" data-job-member="rawRecords" data-index="${index}">
      <div class="record-title">
        <span>${escapeHtml(record.external_id || record.id)}</span>
        <span class="chip">${escapeHtml(record.record_type || "")}</span>
      </div>
      <div class="record-body">${escapeHtml(record.fetched_at || record.created_at || "")}<br />${linkHtml(record.url)}</div>
    </div>
  `).join("") || `<p class="mini">No raw records loaded.</p>`}`;
  artsNode.innerHTML = `${members?.fallback === "source" ? fallbackNotice : ""}${arts.map((art, index) => `
    <div class="record art-record" data-job-member="arts" data-index="${index}">
      <div class="record-title">
        <span>${escapeHtml(art.review_message_kind || art.type || art.id)}</span>
        <span class="chip">${escapeHtml(art.source_created_at || art.imported_at || "")}</span>
        ${art.automated ? `<span class="chip danger">automated</span>` : ""}
      </div>
      ${reviewLocationHtml(art)}
      <div class="record-body">${escapeHtml(preview(art.body || "", 500))}</div>
      <div class="record-body">${linkHtml(art.url)}</div>
    </div>
  `).join("") || `<p class="mini">No arts loaded.</p>`}`;
  jsonNode.innerHTML = members
    ? [
        resultCard("Logs response", members.logsResult),
        resultCard("Raw records response", members.rawRecordsResult),
        resultCard("Arts response", members.artsResult),
        resultCard("Metadata response", members.metadataResult),
        resultCard("Relationships response", members.relationshipsResult),
      ].join("")
    : `<p class="mini">Click Load Job Members or enqueue a job to hydrate member responses.</p>`;
  $$("[data-job-member]").forEach((node) => {
    node.addEventListener("click", () => {
      const key = node.dataset.jobMember;
      const index = Number(node.dataset.index);
      $("#jobDetail").textContent = pretty((displayed[key] || [])[index] || {});
    });
  });
}

function memberPagerHtml(key, members) {
  if (!members) return `<span>Not loaded</span>`;
  const paging = ensureJobMemberPaging(members.jobId);
  const pageState = paging[key] || { cursor: "", history: [] };
  const result = members[`${key}Result`]?.value;
  const prevDisabled = pageState.history.length ? "" : "disabled";
  const nextDisabled = pageCursor(result) ? "" : "disabled";
  return `
    <button data-member-page="${escapeAttr(key)}" data-member-dir="prev" ${prevDisabled}>Prev</button>
    <span>${escapeHtml(pageRangeText(key, members))}</span>
    <button data-member-page="${escapeAttr(key)}" data-member-dir="next" ${nextDisabled}>Next</button>
  `;
}

function pageRangeText(key, members) {
  const records = members?.[key] || [];
  const result = members?.[`${key}Result`]?.value;
  const total = Number(result?.total ?? result?.page?.total ?? records.length ?? 0);
  const paging = ensureJobMemberPaging(members?.jobId);
  const start = Number(paging?.[key]?.cursor || 0);
  if (!total || !records.length) return `0 of ${total}`;
  return `${start + 1}-${Math.min(start + records.length, total)} of ${total}`;
}

function pageCursor(value) {
  return value?.next_cursor || value?.page?.next_cursor || "";
}

async function runJobAction(action) {
  const jobId = state.selected.jobId;
  if (!jobId) return toast("Select an ingestion job first", true);
  const result = await api("repointel", "POST", `/ingestion-jobs/${jobId}/${action}`, {});
  $("#jobDetail").textContent = pretty(result);
  await refreshIngestion();
  toast(`Job ${action} completed`);
}

function renderNormalizers() {
  const normalizers = state.data.normalizers || [];
  $("#normalizerList").innerHTML = normalizers.map((normalizer) => recordCard(normalizer, {
    title: normalizer.name || normalizer.id,
    subtitle: `${normalizer.language || ""} ${normalizer.provider || ""} ${normalizer.source_type || ""} enabled=${normalizer.enabled !== false}`,
    attrs: `data-normalizer-id="${escapeAttr(normalizer.id)}"`,
  })).join("") || `<p class="mini">No normalizers.</p>`;
  $$("#normalizerList .record").forEach((item) => {
    item.addEventListener("click", () => {
      state.selected.normalizerId = item.dataset.normalizerId;
      $("#normalizerTestForm [name='normalizer_id']").value = state.selected.normalizerId;
    });
  });
}

function renderCollectionRuns() {
  const runs = state.data.collectionRuns || [];
  $("#collectionRuns").innerHTML = runs.map((run) => recordCard(run, {
    title: run.id,
    subtitle: `${run.status || ""} hits=${run.evidence_hits_count || 0} metadata=${run.metadata_upserted_count || 0} rel=${run.relationships_upserted_count || 0}`,
    selected: state.selected.collectionRunId === run.id,
    attrs: `data-run-id="${escapeAttr(run.id)}"`,
  })).join("") || `<p class="mini">No collection runs.</p>`;
  $$("#collectionRuns .record").forEach((item) => {
    item.addEventListener("click", () => {
      state.selected.collectionRunId = item.dataset.runId;
      renderCollectionRuns();
    });
  });
}

async function loadRunEvidence() {
  const runId = state.selected.collectionRunId;
  if (!runId) return toast("Select a collection run first", true);
  const result = await api("metadata", "GET", `/runs/${runId}/evidence-hits`);
  state.data.selectedEvidence = items(result);
  renderEvidenceHits(state.data.selectedEvidence);
}

async function loadRunTraces() {
  const runId = state.selected.collectionRunId;
  if (!runId) return toast("Select a collection run first", true);
  const result = await api("metadata", "GET", `/runs/${runId}/downstream-calls`);
  $("#evidenceList").innerHTML = items(result).map((trace) => recordCard(trace, {
    title: trace.operation,
    subtitle: `${trace.method} ${trace.path} status=${trace.status_code}`,
  })).join("");
}

function renderEvidenceHits(hits) {
  $("#evidenceList").innerHTML = hits.map((hit) => `
    <div class="record">
      <div class="record-title">
        <span>${escapeHtml(hit.namespace || "")}.${escapeHtml(hit.key || "")}</span>
        <span class="chip">${escapeHtml(hit.disposition || "")}</span>
      </div>
      <div class="record-body">
        ${escapeHtml(hit.matched_text_preview || "")}<br />
        confidence=${hit.confidence ?? ""} rule=${escapeHtml(hit.rule_id || "")}<br />
        art=${escapeHtml(hit.art_id || "")} metadata=${(hit.proposed_metadata || []).length} rel=${(hit.proposed_relationships || []).length}
      </div>
    </div>
  `).join("") || `<p class="mini">No evidence loaded.</p>`;
}

function renderEvidence() {
  if (!$("#rawRecordsList")) return;
  renderList("#rawRecordsList", state.data.rawRecords, (item) => [item.id, `${item.record_type || ""} ${item.external_id || ""}`]);
  renderList("#artsList", state.data.arts, (item) => [item.id, `${item.type || ""} ${preview(item.body || "", 120)}`]);
  renderList("#authorsList", state.data.authors, (item) => [item.id, `${item.username || ""} ${item.email || ""}`]);
  if (state.data.largeEvidenceCollectionsDeferred && !(state.data.metadata || []).length) {
    $("#metadataList").innerHTML = `<p class="mini">Large collection. Use Analytics for aggregate metadata and DB Browser/search for targeted rows.</p>`;
  } else {
    renderList("#metadataList", state.data.metadata, (item) => [item.id, `${item.namespace || ""}.${item.key || ""} ${JSON.stringify(item.value ?? "")}`]);
  }
  if (state.data.largeEvidenceCollectionsDeferred && !(state.data.relationships || []).length) {
    $("#relationshipsList").innerHTML = `<p class="mini">Large collection. Use Analytics for relationship charts and DB Browser/search for targeted rows.</p>`;
  } else {
    renderList("#relationshipsList", state.data.relationships, (item) => [item.id, `${item.from_type}:${item.from_id} ${item.relation} ${item.to_type}:${item.to_id}`]);
  }
}

function renderAnalytics() {
  const data = state.data.analytics;
  const cards = $("#analyticsCards");
  if (!cards) return;
  if (!data) {
    cards.innerHTML = state.data.analyticsError
      ? `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(state.data.analyticsError)}</div></div>`
      : `<div class="stat-card"><div class="value">-</div><div class="label">Analytics not loaded</div></div>`;
    clearAnalyticsCharts();
    return;
  }

  const collectionCount = (collection) => Number((data.collection_counts || []).find((row) => row.collection === collection)?.count || 0);
  const linkCount = (origin) => Number((data.relationship_by_origin || []).find((row) => row.origin === origin)?.count || 0);
  cards.innerHTML = [
    ["Raw", collectionCount("raw-records")],
    ["Arts", collectionCount("arts")],
    ["Authors", collectionCount("authors")],
    ["Metadata", collectionCount("metadata")],
    ["Relationships", collectionCount("relationships")],
    ["Commit-Bug Links", linkCount("normalizer.metadata_link.commit_bug")],
    ["Approval Links", linkCount("normalizer.metadata_link.approval_change")],
    ["Change-File Links", linkCount("normalizer.metadata_link.gerrit_change_file")],
  ].map(([label, value]) => statCard(label, formatNumber(value))).join("");

  drawSourceStackedChart("#sourceStackedChart", data.source_counts || []);
  drawRecordMixChart("#recordMixChart", data);
  drawDonutChart("#automationChart", (data.automation_counts || []).map((row) => ({
    label: row.automated === "true" ? "Automated" : "Developer / other",
    value: Number(row.count || 0),
  })));
  drawHorizontalBarChart(
    "#metadataCoverageChart",
    (data.metadata_by_namespace_key || []).slice(0, 28),
    (row) => `${row.namespace}.${row.key}`,
    (row) => Number(row.count || 0),
    { color: "#245da8" },
  );
  drawHorizontalBarChart(
    "#relationshipOriginChart",
    (data.relationship_by_origin || []).slice(0, 24),
    (row) => row.origin,
    (row) => Number(row.count || 0),
    { color: "#146c63" },
  );

  const scenarios = buildScenarioReadiness(data);
  drawScenarioChart("#scenarioReadinessChart", scenarios);
  renderAnalyticsTable("#scenarioReadinessTable", ["Idea", "Status", "Present", "Missing"], scenarios, (row) => [
    row.idea,
    row.status,
    row.present.join(", "),
    row.missing.join(", "),
  ]);
  renderAnalyticsTable("#securitySignalsTable", ["Signal", "Count"], data.security_signals || [], (row) => [row.key, row.count]);
  renderAnalyticsTable("#topComponentsTable", ["Component", "Count"], data.top_components || [], (row) => [stripJsonScalar(row.component), row.count]);
  renderAnalyticsTable("#topFilesTable", ["File", "Count"], data.top_files || [], (row) => [stripJsonScalar(row.path), row.count]);
  renderAnalyticsTable("#recentJobsTable", ["Job", "Status", "Mode", "Arts", "Metadata", "Relationships"], data.recent_jobs || [], (row) => [
    row.id,
    row.status,
    row.mode,
    row.arts_count,
    row.metadata_count,
    row.relationships_count,
  ]);
  renderAnalyticsTable("#metadataLinkSamplesTable", ["Origin", "From", "Relation", "To"], data.metadata_link_samples || [], (row) => [
    row.origin,
    `${row.from_namespace}.${row.from_key}=${stripJsonScalar(row.from_value)}`,
    row.relation,
    `${row.to_namespace}.${row.to_key}=${stripJsonScalar(row.to_value)}`,
  ]);
}

function renderIdeas() {
  const data = state.data.analytics;
  const cards = $("#ideaSummaryCards");
  if (!cards) return;
  if (!data) {
    cards.innerHTML = state.data.analyticsError
      ? `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(state.data.analyticsError)}</div></div>`
      : `<div class="stat-card"><div class="value">-</div><div class="label">Ideas not loaded</div></div>`;
    clearIdeaCharts();
    return;
  }

  const ideas = buildIdeaReadiness(data);
  const signalCapture = buildSignalCaptureMatrix(data);
  const signals = ideaSignalRows(data);
  const available = ideas.filter((idea) => idea.status === "available").length;
  const partial = ideas.filter((idea) => idea.status === "partial").length;
  const missing = ideas.filter((idea) => idea.status === "missing").length;
  const avgScore = Math.round(ideas.reduce((sum, idea) => sum + idea.score, 0) / Math.max(1, ideas.length));
  cards.innerHTML = [
    ["Ideas", ideas.length],
    ["Available", available],
    ["Partial", partial],
    ["Missing", missing],
    ["Avg Score", `${avgScore}%`],
    ["Signals Present", signals.filter((row) => row.count > 0).length],
  ].map(([label, value]) => statCard(label, value)).join("");

  drawSignalCaptureChart("#signalCaptureChart", signalCapture);
  renderAnalyticsTable(
    "#signalCaptureTable",
    ["Signal", "Status", "Coverage", "Evidence", "Missing / Weak"],
    signalCapture,
    (row) => [
      row.signal,
      row.status,
      `${row.coverage}%`,
      row.present.join(" | "),
      row.missing.join(", "),
    ],
  );
  drawTopScoreChart("#changeChurnChart", data.change_churn_hotspots || [], (row) => `Change ${row.change_number}`, "churn_score", "#b54708");
  renderAnalyticsTable(
    "#changeChurnTable",
    [
      "Change",
      "Status",
      "Patch Sets",
      "Files",
      "Insertions",
      "Deletions",
      "Changed Lines",
      "Unresolved",
      "Score",
      "Subject",
    ],
    data.change_churn_hotspots || [],
    (row) => [
      row.change_number,
      row.status,
      row.patch_sets,
      row.touched_files,
      row.insertions,
      row.deletions,
      row.changed_lines,
      row.unresolved_comments,
      row.churn_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#crossArtifactChart", data.cross_artifact_convergence || [], (row) => `Change ${row.change_number}`, "convergence_score", "#245da8");
  renderAnalyticsTable(
    "#crossArtifactTable",
    [
      "Change",
      "Status",
      "Review Msgs",
      "Human",
      "Auto",
      "Security Msgs",
      "Votes",
      "Components",
      "Files",
      "Score",
      "Subject",
    ],
    data.cross_artifact_convergence || [],
    (row) => [
      row.change_number,
      row.status,
      row.review_messages,
      row.human_messages,
      row.automated_messages,
      row.security_signal_messages,
      row.vote_events,
      row.components,
      row.files,
      row.convergence_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#reviewFrictionChart", data.review_friction_changes || [], (row) => `Change ${row.change_number}`, "friction_score", "#b42318");
  renderAnalyticsTable(
    "#reviewFrictionTable",
    ["Change", "Status", "Patch Sets", "Comments", "Unresolved", "Neg Votes", "Score", "Subject"],
    data.review_friction_changes || [],
    (row) => [
      row.change_number,
      row.status,
      row.patch_sets,
      row.total_comments,
      row.unresolved_comments,
      row.negative_votes,
      row.friction_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#contradictedApprovalChart", data.contradicted_approval_changes || [], (row) => `Change ${row.change_number}`, "contradiction_score", "#8b1e3f");
  renderAnalyticsTable(
    "#contradictedApprovalTable",
    ["Change", "Status", "Reviewers", "+ Votes", "- Votes", "Unresolved", "Score", "Subject"],
    data.contradicted_approval_changes || [],
    (row) => [
      row.change_number,
      row.status,
      row.reviewers,
      row.positive_votes,
      row.negative_votes,
      row.unresolved_comments,
      row.contradiction_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#reviewAbandonmentChart", data.review_abandonment_changes || [], (row) => `Change ${row.change_number}`, "abandonment_score", "#a56315");
  renderAnalyticsTable(
    "#reviewAbandonmentTable",
    ["Change", "Status", "Patch Sets", "Comments", "Unresolved", "Score", "Subject"],
    data.review_abandonment_changes || [],
    (row) => [
      row.change_number,
      row.status,
      row.patch_sets,
      row.total_comments,
      row.unresolved_comments,
      row.abandonment_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#bugThreadHotspotChart", data.bug_thread_hotspots || [], (row) => `Bug ${row.bug_id}`, "exposure_score", "#245da8");
  renderAnalyticsTable(
    "#bugThreadHotspotTable",
    ["Bug", "Status", "Importance", "Heat", "Msgs", "Dupes", "Affected", "Sec", "Private", "Score", "Title"],
    data.bug_thread_hotspots || [],
    (row) => [
      row.bug_id,
      row.status,
      row.importance,
      row.heat,
      row.message_count,
      row.duplicate_count,
      row.users_affected_count,
      row.security_related,
      row.private_bug,
      row.exposure_score,
      row.title,
    ],
  );
  drawTopScoreChart("#componentHotspotChart", data.component_hotspots || [], (row) => row.component, "hotspot_score", "#146c63");
  renderAnalyticsTable(
    "#componentHotspotTable",
    ["Component", "Review Changes", "Security Reviews", "Score"],
    data.component_hotspots || [],
    (row) => [
      row.component,
      row.review_changes,
      row.security_signal_reviews,
      row.hotspot_score,
    ],
  );
  drawTopScoreChart("#fileHotspotChart", data.file_hotspots || [], (row) => row.path, "hotspot_score", "#245da8");
  renderAnalyticsTable(
    "#fileHotspotTable",
    ["File", "Review Changes", "Security Reviews", "Score"],
    data.file_hotspots || [],
    (row) => [
      row.path,
      row.review_changes,
      row.security_signal_reviews,
      row.hotspot_score,
    ],
  );
  drawTopScoreChart("#silentSecurityFixChart", data.silent_security_fix_candidates || [], (row) => row.commit_sha, "candidate_score", "#b42318");
  renderAnalyticsTable(
    "#silentSecurityFixTable",
    ["Commit", "Author", "Signal Mentions", "Signal Kinds", "Score", "Preview"],
    data.silent_security_fix_candidates || [],
    (row) => [
      row.commit_sha,
      row.author_id,
      row.security_signal_mentions,
      row.distinct_signal_kinds,
      row.candidate_score,
      row.body_preview,
    ],
  );
  drawTopScoreChart("#componentConcentrationChart", data.component_concentration || [], (row) => row.component, "concentration_score", "#7a5af8");
  renderAnalyticsTable(
    "#componentConcentrationTable",
    ["Component", "Review Changes", "Authors", "Changes / Author", "Security Reviews", "Score"],
    data.component_concentration || [],
    (row) => [
      row.component,
      row.review_changes,
      row.distinct_authors,
      row.changes_per_author,
      row.security_signal_reviews,
      row.concentration_score,
    ],
  );
  drawTopScoreChart("#sensitiveSurfaceChart", data.sensitive_surface_hotspots || [], (row) => row.component, "hotspot_score", "#b42318");
  renderAnalyticsTable(
    "#sensitiveSurfaceTable",
    ["Component", "Security Reviews", "Signal Kinds", "Score"],
    data.sensitive_surface_hotspots || [],
    (row) => [
      row.component,
      row.security_signal_reviews,
      row.distinct_signal_kinds,
      row.hotspot_score,
    ],
  );
  drawTopScoreChart("#sensitiveDisagreementChart", data.sensitive_review_disagreement || [], (row) => `Change ${row.change_number}`, "disagreement_score", "#8b1e3f");
  renderAnalyticsTable(
    "#sensitiveDisagreementTable",
    ["Change", "Status", "+ Votes", "- Votes", "Signal Mentions", "Signal Kinds", "Unresolved", "Score", "Subject"],
    data.sensitive_review_disagreement || [],
    (row) => [
      row.change_number,
      row.status,
      row.positive_votes,
      row.negative_votes,
      row.security_signal_mentions,
      row.distinct_signal_kinds,
      row.unresolved_comments,
      row.disagreement_score,
      row.subject,
    ],
  );
  drawTopScoreChart("#reviewAutomationChart", data.review_automation_balance || [], (row) => `Change ${row.change_number}`, "automated_ratio", "#0f766e");
  renderAnalyticsTable(
    "#reviewAutomationTable",
    ["Change", "Status", "Total Msgs", "Human", "Auto", "Auto Ratio", "Subject"],
    data.review_automation_balance || [],
    (row) => [
      row.change_number,
      row.status,
      row.total_messages,
      row.human_messages,
      row.automated_messages,
      row.automated_ratio,
      row.subject,
    ],
  );
  drawTopScoreChart("#dependencyHotspotChart", data.dependency_hotspots || [], (row) => row.path, "hotspot_score", "#7a5af8");
  renderAnalyticsTable(
    "#dependencyHotspotTable",
    ["Path", "Mentions", "Distinct Subjects", "Score"],
    data.dependency_hotspots || [],
    (row) => [
      row.path,
      row.touched_changes,
      row.distinct_subjects,
      row.hotspot_score,
    ],
  );
  drawTopScoreChart("#workflowHotspotChart", data.workflow_hotspots || [], (row) => row.path, "hotspot_score", "#0f766e");
  renderAnalyticsTable(
    "#workflowHotspotTable",
    ["Path", "Mentions", "Distinct Subjects", "Score"],
    data.workflow_hotspots || [],
    (row) => [
      row.path,
      row.touched_changes,
      row.distinct_subjects,
      row.hotspot_score,
    ],
  );
  drawIdeaReadinessChart("#ideaReadinessChart", ideas);
  drawIdeaHeatmapChart("#ideaHeatmapChart", ideas, signals);
  drawHorizontalBarChart(
    "#ideaSignalChart",
    signals,
    (row) => row.label,
    (row) => row.count,
    { color: "#245da8" },
  );
  renderAnalyticsTable(
    "#ideaTable",
    ["#", "Idea", "Score", "Status", "Evidence Counts", "Missing"],
    ideas,
    (idea) => [
      idea.number,
      idea.idea,
      `${idea.score}%`,
      idea.status,
      idea.metrics.map((metric) => `${metric.label}: ${formatNumber(metric.count)}`).join(" | "),
      idea.missing.join(", "),
    ],
  );
  renderAnalyticsTable("#ideaSecuritySignalsTable", ["Signal", "Count"], data.security_signals || [], (row) => [row.key, row.count]);
  renderAnalyticsTable("#ideaComponentsTable", ["Component", "Count"], data.top_components || [], (row) => [stripJsonScalar(row.component), row.count]);
  renderAnalyticsTable("#ideaLinkEvidenceTable", ["Origin", "From", "Relation", "To"], data.metadata_link_samples || [], (row) => [
    row.origin,
    `${row.from_namespace}.${row.from_key}=${stripJsonScalar(row.from_value)}`,
    row.relation,
    `${row.to_namespace}.${row.to_key}=${stripJsonScalar(row.to_value)}`,
  ]);
}

function renderReviewRisk() {
  const data = state.data.reviewRisk;
  const cards = $("#reviewRiskCards");
  if (!cards) return;
  if (!data) {
    cards.innerHTML = state.data.reviewRiskError
      ? `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(state.data.reviewRiskError)}</div></div>`
      : `<div class="stat-card"><div class="value">-</div><div class="label">Review risk not loaded</div></div>`;
    clearReviewRiskCharts();
    return;
  }

  const summary = data.review_risk_summary || {};
  const filters = data.filters || {};
  const rows = data.proposed_review_risk || [];
  ensureReviewRiskDecisionDefaults();
  const scenario = reviewRiskDecisionScenario(rows);
  renderReviewRiskCards(summary, filters, rows, scenario);
  renderReviewRiskDecisionControls(scenario);
  renderReviewRiskDecisionOutput(scenario);
  renderAnalyticsTable(
    "#reviewRiskWeightsTable",
    ["Bucket", "Field", "Weight"],
    data.review_risk_weights || [],
    (row) => [row.bucket, row.field, row.weight],
  );
}

function clearReviewRiskCharts() {
  for (const selector of ["#reviewRiskDecisionGraph", "#reviewRiskDecisionSummary", "#reviewRiskDecisionControls", "#reviewRiskTable", "#reviewRiskWeightsTable", "#reviewRiskSelectedDetail"]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function clearReviewRiskResultViews() {
  for (const selector of ["#reviewRiskDecisionGraph", "#reviewRiskDecisionSummary", "#reviewRiskTable", "#reviewRiskWeightsTable", "#reviewRiskSelectedDetail"]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function ensureReviewRiskDecisionDefaults() {
  state.reviewRiskDecision ||= { lastDays: 365, limit: 1000, mergedOnly: false, controls: {} };
  state.reviewRiskDecision.lastDays = clampNumber(state.reviewRiskDecision.lastDays || 365, 1, 1825);
  state.reviewRiskDecision.limit = clampNumber(state.reviewRiskDecision.limit || 1000, 100, 2000);
  state.reviewRiskDecision.mergedOnly = Boolean(state.reviewRiskDecision.mergedOnly);
  state.reviewRiskDecision.controls ||= {};
  for (const signal of reviewRiskDecisionSignals) {
    state.reviewRiskDecision.controls[signal.id] ||= {
      min: 0,
      max: 100,
      weight: signal.weight,
    };
    const control = state.reviewRiskDecision.controls[signal.id];
    control.min = clampNumber(control.min, 0, 100);
    control.max = clampNumber(control.max, 0, 100);
    control.weight = clampNumber(control.weight ?? signal.weight, 0, 3);
    if (control.min > control.max) {
      const midpoint = control.min;
      control.min = control.max;
      control.max = midpoint;
    }
  }
  syncReviewRiskFormControls();
}

function reviewRiskDecisionControl(signalId) {
  ensureReviewRiskDecisionDefaults();
  return state.reviewRiskDecision.controls[signalId];
}

function renderReviewRiskCards(summary, filters, rows, scenario) {
  const cards = $("#reviewRiskCards");
  if (!cards) return;
  const visibleRows = scenario?.filteredRows || rows || [];
  cards.innerHTML = [
    ["Reviews", formatNumber(summary.proposed_reviews || 0)],
    ["Visible", `${formatNumber(visibleRows.length)} / ${formatNumber((rows || []).length)}`],
    ["Urgent", formatNumber(summary.urgent_reviews ?? summary.critical_reviews ?? 0)],
    ["High+", formatNumber(summary.high_compute_reviews ?? summary.high_reviews ?? 0)],
    ["Avg Priority", summary.avg_risk_score ?? 0],
    ["Max Priority", formatNumber(summary.max_risk_score || 0)],
    ["Last Days", formatNumber(state.reviewRiskDecision?.lastDays || 365)],
    ["Filter", reviewRiskFilterLabel(filters)],
  ].map(([label, value]) => statCard(label, value)).join("");
}

function reviewRiskDecisionScenario(rows = []) {
  ensureReviewRiskDecisionDefaults();
  const scenarioRows = (rows || []).map(reviewRiskDecisionRow);
  const stats = {};
  for (const signal of reviewRiskDecisionSignals) {
    const control = reviewRiskDecisionControl(signal.id);
    let kept = 0;
    let dropped = 0;
    let missing = 0;
    for (const row of scenarioRows) {
      const value = row.decision_values[signal.id];
      if (value === null || value === undefined) {
        missing += 1;
        if (control.min <= 0 && control.max >= 100) kept += 1;
        else dropped += 1;
      } else if (value >= control.min && value <= control.max) {
        kept += 1;
      } else {
        dropped += 1;
      }
    }
    stats[signal.id] = { kept, dropped, missing };
  }
  let dateKept = 0;
  let dateDropped = 0;
  const filteredRows = scenarioRows
    .filter((row) => {
      const keep = reviewRiskWithinLastDays(row, state.reviewRiskDecision.lastDays);
      if (keep) dateKept += 1;
      else dateDropped += 1;
      return keep;
    })
    .filter((row) => reviewRiskDecisionSignals.every((signal) => reviewRiskSignalInRange(row, signal.id)))
    .sort((a, b) => b.scenario_score - a.scenario_score || b.risk_score - a.risk_score || String(a.change_number).localeCompare(String(b.change_number)));
  return {
    rows: scenarioRows,
    filteredRows,
    stats,
    lastDays: {
      kept: dateKept,
      dropped: dateDropped,
    },
  };
}

function reviewRiskDecisionRow(row) {
  const values = {};
  for (const signal of reviewRiskDecisionSignals) {
    values[signal.id] = reviewRiskDecisionSignalValue(row, signal.id);
  }
  const contributors = reviewRiskScenarioContributors(values);
  const weightedSum = contributors.reduce((sum, item) => sum + item.weighted_value, 0);
  const denominator = contributors.reduce((sum, item) => sum + item.weight, 0);
  const scenarioScore = denominator > 0 ? weightedSum / denominator : Number(row.bucket_score || 0);
  return {
    ...row,
    repo_label: reviewRiskRepoLabel(row),
    decision_values: values,
    scenario_score: roundNumber(clampNumber(scenarioScore, 0, 100), 1),
    scenario_contributors: contributors
      .map((item) => ({
        ...item,
        percent: weightedSum > 0 ? roundNumber((item.weighted_value / weightedSum) * 100, 1) : 0,
      }))
      .sort((a, b) => b.weighted_value - a.weighted_value),
  };
}

function reviewRiskScenarioContributors(values) {
  const contributors = [];
  for (const signal of reviewRiskDecisionSignals) {
    const value = values[signal.id];
    if (value === null || value === undefined) continue;
    const control = reviewRiskDecisionControl(signal.id);
    const weight = clampNumber(control.weight, 0, 3);
    contributors.push({
      id: signal.id,
      label: signal.label,
      color: signal.color,
      score: clampNumber(value, 0, 100),
      weight,
      weighted_value: clampNumber(value, 0, 100) * weight,
    });
  }
  return contributors;
}

function reviewRiskDecisionSignalValue(row, signalId) {
  switch (signalId) {
    case "security_sensitivity":
      return maxNullable([
        reviewRiskScoreItem(row, "security_sensitivity_score"),
        reviewRiskScoreItem(row, "security_keyword_score"),
        numericField(row, "sensitivity_weighted_score"),
        numericField(row, "max_sensitivity_score"),
      ]);
    case "author_competence":
      return maxNullable([reviewRiskScoreItem(row, "author_competence_score"), numericField(row, "author_score")]);
    case "reviewer_competence":
      return maxNullable([reviewRiskScoreItem(row, "reviewer_survival_score"), numericField(row, "reviewer_score")]);
    case "review_churn":
      return maxNullable([reviewRiskScoreItem(row, "review_churn_score"), numericField(row, "rework_score")]);
    case "review_friction":
      return maxNullable([reviewRiskScoreItem(row, "review_friction_score"), numericField(row, "friction_score")]);
    case "review_comment_smell":
      return maxNullable([reviewRiskScoreItem(row, "implementation_concern_score"), numericField(row, "implementation_score")]);
    case "loc_changed":
      return maxNullable([reviewRiskScoreItem(row, "changed_lines_score"), numericField(row, "changed_lines_score")]);
    case "file_surface":
      return maxNullable([
        reviewRiskScoreItem(row, "security_file_surface_score"),
        rowHasAnyField(row, ["security_sensitive_files", "attack_surface_files", "dependency_files", "workflow_files"])
          ? Number(row.security_sensitive_files || 0) * 28
            + Number(row.attack_surface_files || 0) * 22
            + Number(row.dependency_files || 0) * 16
            + Number(row.workflow_files || 0) * 16
          : null,
      ]);
    case "bug_linkage":
      return maxNullable([
        numericField(row, "bug_linkage_score"),
        numericField(row, "linked_bug_score"),
        numericField(row, "linked_bugs_score"),
        numericField(row, "linked_bug_count") == null ? null : Number(row.linked_bug_count || 0) * 20,
        numericField(row, "linked_bugs_count") == null ? null : Number(row.linked_bugs_count || 0) * 20,
      ]);
    case "bug_comment_smell":
      return maxNullable([
        numericField(row, "bug_comment_smell_score"),
        numericField(row, "bug_comment_concern_score"),
        numericField(row, "linked_bug_comment_smell_score"),
      ]);
    case "commit_comment_smell":
      return maxNullable([
        numericField(row, "commit_comment_smell_score"),
        numericField(row, "commit_message_smell_score"),
        numericField(row, "commit_concern_score"),
      ]);
    case "staleness":
      return maxNullable([reviewRiskScoreItem(row, "staleness_score"), numericField(row, "stale_score")]);
    default:
      return null;
  }
}

function reviewRiskScoreItem(row, scoreId) {
  const items = Array.isArray(row.score_items) ? row.score_items : Array.isArray(row.bucket_score_details?.items) ? row.bucket_score_details.items : [];
  const item = items.find((entry) => entry?.score_id === scoreId);
  return item ? clampNumber(Number(item.score || 0), 0, 100) : null;
}

function numericField(row, field) {
  if (!Object.prototype.hasOwnProperty.call(row || {}, field)) return null;
  const value = Number(row[field]);
  return Number.isFinite(value) ? clampNumber(value, 0, 100) : null;
}

function rowHasAnyField(row, fields) {
  return fields.some((field) => Object.prototype.hasOwnProperty.call(row || {}, field));
}

function maxNullable(values) {
  const numbers = values
    .filter((value) => value !== null && value !== undefined)
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
  return numbers.length ? clampNumber(Math.max(...numbers), 0, 100) : null;
}

function reviewRiskSignalInRange(row, signalId) {
  const control = reviewRiskDecisionControl(signalId);
  const value = row.decision_values?.[signalId];
  if (value === null || value === undefined) return control.min <= 0 && control.max >= 100;
  return value >= control.min && value <= control.max;
}

function reviewRiskWithinLastDays(row, days) {
  const timestamp = Date.parse(row.updated_at || row.created_at || "");
  if (!Number.isFinite(timestamp)) return true;
  return timestamp >= Date.now() - clampNumber(days || 365, 1, 1825) * 24 * 60 * 60 * 1000;
}

function reviewRiskRepoLabel(row) {
  const project = String(row.project || "").trim();
  if (project) return project.replace(/^openstack\//, "");
  return String(row.repository_id || "unknown").replace(/^repository-/, "repo-");
}

function renderReviewRiskDecisionControls(scenario) {
  const node = $("#reviewRiskDecisionControls");
  if (!node) return;
  ensureReviewRiskDecisionDefaults();
  const data = state.data.reviewRisk || {};
  const totalScored = data.review_risk_summary?.proposed_reviews || 0;
  const returnedRows = (data.proposed_review_risk || []).length;
  node.innerHTML = `
    <div class="decision-controls-head">
      <div>
        <strong>Decision Filters & Weights</strong>
        <span>Scenario layer over persisted score items</span>
      </div>
      <div class="decision-controls-actions">
        <label class="decision-inline-check">
          <input type="checkbox" data-review-risk-merged-only ${state.reviewRiskDecision.mergedOnly ? "checked" : ""} />
          <span>Merged only</span>
        </label>
        <span data-review-risk-visible-count>${formatNumber(scenario.filteredRows.length)} shown</span>
      </div>
    </div>
    <div class="decision-control decision-control-limit">
      <div class="decision-control-title">
        <span>Returned Rows</span>
        <small><span data-review-risk-limit-meta>${formatNumber(returnedRows)} returned / ${formatNumber(totalScored)} scored</span> | <span data-review-risk-limit-value>${formatNumber(state.reviewRiskDecision.limit)}</span></small>
      </div>
      <div class="decision-compact-slider decision-limit-slider">
        <span>limit</span>
        <button type="button" data-review-risk-limit-adjust="1" data-delta="-100">-</button>
        <input type="range" min="100" max="2000" step="50" value="${escapeAttr(state.reviewRiskDecision.limit)}" data-review-risk-limit-slider="1" />
        <button type="button" data-review-risk-limit-adjust="1" data-delta="100">+</button>
      </div>
    </div>
    <div class="decision-control decision-control-last-days">
      <div class="decision-control-title">
        <span>Last X Days</span>
        <small><span data-review-risk-last-days-meta>${reviewRiskLastDaysText(scenario)}</span> | <span data-review-risk-last-days-value>${formatNumber(state.reviewRiskDecision.lastDays)} days</span></small>
      </div>
      <div class="decision-compact-slider decision-days-slider">
        <span>window</span>
        <button type="button" data-review-risk-decision-adjust="1" data-field="last_days" data-delta="-30">-</button>
        <input type="range" min="1" max="1825" step="1" value="${escapeAttr(state.reviewRiskDecision.lastDays)}" data-review-risk-decision-slider="1" data-field="last_days" />
        <button type="button" data-review-risk-decision-adjust="1" data-field="last_days" data-delta="30">+</button>
      </div>
    </div>
    ${reviewRiskDecisionSignals.map((signal) => renderReviewRiskDecisionControl(signal, scenario.stats[signal.id])).join("")}
  `;
}

function renderReviewRiskDecisionControl(signal, stat = {}) {
  const control = reviewRiskDecisionControl(signal.id);
  return `
    <div class="decision-control" data-review-risk-decision-control="${escapeAttr(signal.id)}">
      <div class="decision-control-title">
        <span>${escapeHtml(signal.label)}</span>
        <small><span data-control-meta>${reviewRiskDecisionStatText(stat)}</span> | <span data-current-range>${formatNumber(control.min)}-${formatNumber(control.max)}</span> | <span data-current-weight>${control.weight.toFixed(1)}x</span></small>
      </div>
      <div class="decision-compact-sliders">
        <div class="decision-compact-slider">
          <span>range</span>
          <button type="button" data-review-risk-decision-adjust="1" data-signal-id="${escapeAttr(signal.id)}" data-field="min" data-delta="-2">-</button>
          <div class="decision-range-stack">
            <input type="range" min="0" max="100" step="1" value="${escapeAttr(control.min)}" data-review-risk-decision-slider="1" data-signal-id="${escapeAttr(signal.id)}" data-field="min" />
            <input type="range" min="0" max="100" step="1" value="${escapeAttr(control.max)}" data-review-risk-decision-slider="1" data-signal-id="${escapeAttr(signal.id)}" data-field="max" />
          </div>
          <button type="button" data-review-risk-decision-adjust="1" data-signal-id="${escapeAttr(signal.id)}" data-field="max" data-delta="2">+</button>
        </div>
        <div class="decision-compact-slider">
          <span>weight</span>
          <button type="button" data-review-risk-decision-adjust="1" data-signal-id="${escapeAttr(signal.id)}" data-field="weight" data-delta="-0.1">-</button>
          <input type="range" min="0" max="3" step="0.1" value="${escapeAttr(control.weight)}" data-review-risk-decision-slider="1" data-signal-id="${escapeAttr(signal.id)}" data-field="weight" />
          <button type="button" data-review-risk-decision-adjust="1" data-signal-id="${escapeAttr(signal.id)}" data-field="weight" data-delta="0.1">+</button>
        </div>
      </div>
    </div>
  `;
}

function reviewRiskDecisionStatText(stat = {}) {
  const missing = Number(stat.missing || 0);
  const suffix = missing ? `, ${formatNumber(missing)} no data` : "";
  return `${formatNumber(stat.kept || 0)} kept / ${formatNumber(stat.dropped || 0)} dropped${suffix}`;
}

function reviewRiskLastDaysText(scenario) {
  const kept = Number(scenario?.lastDays?.kept || 0);
  const dropped = Number(scenario?.lastDays?.dropped || 0);
  return `${formatNumber(kept)} / ${formatNumber(kept + dropped)} returned in window`;
}

function updateReviewRiskLimitFromInput(input, options = {}) {
  ensureReviewRiskDecisionDefaults();
  state.reviewRiskDecision.limit = clampNumber(Number(input.value || 1000), 100, 2000);
  syncReviewRiskLimitInput();
  if (options.refresh) refreshReviewRisk();
}

function adjustReviewRiskLimit(button) {
  ensureReviewRiskDecisionDefaults();
  const delta = Number(button.dataset.delta || 0);
  state.reviewRiskDecision.limit = clampNumber(Number(state.reviewRiskDecision.limit || 1000) + delta, 100, 2000);
  syncReviewRiskLimitInput();
  refreshReviewRisk();
}

function updateReviewRiskDecisionFromInput(slider) {
  ensureReviewRiskDecisionDefaults();
  const field = slider.dataset.field || "";
  if (field === "last_days") {
    state.reviewRiskDecision.lastDays = clampNumber(Number(slider.value || 365), 1, 1825);
    return renderReviewRiskDecisionOutput();
  }
  const control = reviewRiskDecisionControl(slider.dataset.signalId || "");
  if (!control) return;
  if (field === "weight") {
    control.weight = clampNumber(Number(slider.value || 0), 0, 3);
  } else if (field === "min") {
    control.min = clampNumber(Number(slider.value || 0), 0, 100);
    if (control.min > control.max) control.max = control.min;
  } else if (field === "max") {
    control.max = clampNumber(Number(slider.value || 100), 0, 100);
    if (control.max < control.min) control.min = control.max;
  }
  syncReviewRiskDecisionControlInputs(slider.dataset.signalId || "");
  renderReviewRiskDecisionOutput();
}

function adjustReviewRiskDecisionControl(button) {
  ensureReviewRiskDecisionDefaults();
  const field = button.dataset.field || "";
  const delta = Number(button.dataset.delta || 0);
  if (field === "last_days") {
    state.reviewRiskDecision.lastDays = clampNumber(Number(state.reviewRiskDecision.lastDays || 365) + delta, 1, 1825);
    syncReviewRiskDecisionLastDaysInput();
    return renderReviewRiskDecisionOutput();
  }
  const signalId = button.dataset.signalId || "";
  const control = reviewRiskDecisionControl(signalId);
  if (!control) return;
  if (field === "weight") control.weight = clampNumber(roundNumber(control.weight + delta, 1), 0, 3);
  if (field === "min") control.min = clampNumber(control.min + delta, 0, control.max);
  if (field === "max") control.max = clampNumber(control.max + delta, control.min, 100);
  syncReviewRiskDecisionControlInputs(signalId);
  renderReviewRiskDecisionOutput();
}

function syncReviewRiskDecisionLastDaysInput() {
  const value = state.reviewRiskDecision.lastDays;
  const input = $("[data-review-risk-decision-slider][data-field='last_days']");
  if (input) input.value = String(value);
}

function syncReviewRiskLimitInput() {
  const value = state.reviewRiskDecision.limit;
  const input = $("[data-review-risk-limit-slider]");
  if (input) input.value = String(value);
  const text = $("[data-review-risk-limit-value]");
  if (text) text.textContent = formatNumber(value);
  syncReviewRiskFormControls();
}

function syncReviewRiskFormControls() {
  const form = $("#reviewRiskFilters");
  if (!form) return;
  const limit = form.elements.namedItem("limit");
  if (limit) limit.value = String(state.reviewRiskDecision?.limit || 1000);
  const status = form.elements.namedItem("status");
  if (status) status.value = state.reviewRiskDecision?.mergedOnly ? "MERGED" : "NEW";
}

function syncReviewRiskDecisionControlInputs(signalId) {
  const root = $(`[data-review-risk-decision-control="${signalId}"]`);
  if (!root) return;
  const control = reviewRiskDecisionControl(signalId);
  for (const input of $$("[data-review-risk-decision-slider]", root)) {
    if (input.dataset.field === "min") input.value = String(control.min);
    if (input.dataset.field === "max") input.value = String(control.max);
    if (input.dataset.field === "weight") input.value = String(control.weight);
  }
}

function updateReviewRiskDecisionControlStats(scenario) {
  const visible = $("[data-review-risk-visible-count]");
  if (visible) visible.textContent = `${formatNumber(scenario.filteredRows.length)} shown`;
  const data = state.data.reviewRisk || {};
  const limitMeta = $("[data-review-risk-limit-meta]");
  if (limitMeta) {
    limitMeta.textContent = `${formatNumber((data.proposed_review_risk || []).length)} returned / ${formatNumber(data.review_risk_summary?.proposed_reviews || 0)} scored`;
  }
  const limitValue = $("[data-review-risk-limit-value]");
  if (limitValue) limitValue.textContent = formatNumber(state.reviewRiskDecision.limit || 1000);
  const lastValue = $("[data-review-risk-last-days-value]");
  if (lastValue) lastValue.textContent = `${formatNumber(state.reviewRiskDecision.lastDays)} days`;
  const lastMeta = $("[data-review-risk-last-days-meta]");
  if (lastMeta) lastMeta.textContent = reviewRiskLastDaysText(scenario);
  syncReviewRiskDecisionLastDaysInput();
  for (const signal of reviewRiskDecisionSignals) {
    const root = $(`[data-review-risk-decision-control="${signal.id}"]`);
    if (!root) continue;
    const control = reviewRiskDecisionControl(signal.id);
    const meta = $("[data-control-meta]", root);
    if (meta) meta.textContent = reviewRiskDecisionStatText(scenario.stats[signal.id]);
    const range = $("[data-current-range]", root);
    if (range) range.textContent = `${formatNumber(control.min)}-${formatNumber(control.max)}`;
    const weight = $("[data-current-weight]", root);
    if (weight) weight.textContent = `${control.weight.toFixed(1)}x`;
    syncReviewRiskDecisionControlInputs(signal.id);
  }
}

function renderReviewRiskDecisionOutput(scenario = null) {
  const data = state.data.reviewRisk;
  if (!data) return;
  const rows = data.proposed_review_risk || [];
  const current = scenario || reviewRiskDecisionScenario(rows);
  state.data.reviewRiskDecisionScenario = current;
  if (!current.filteredRows.some((row) => String(row.change_number) === String(state.selected.reviewRiskChangeNumber))) {
    state.selected.reviewRiskChangeNumber = current.filteredRows[0]?.change_number || "";
  }
  renderReviewRiskCards(data.review_risk_summary || {}, data.filters || {}, rows, current);
  updateReviewRiskDecisionControlStats(current);
  drawReviewRiskDecisionGraph("#reviewRiskDecisionGraph", current.filteredRows);
  renderReviewRiskDecisionSummary(current.filteredRows);
  renderReviewRiskTable("#reviewRiskTable", current.filteredRows);
}

function drawReviewRiskDecisionGraph(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  if (!rows.length) return emptyChart(node);
  const lanes = Array.from(new Set(rows.map((row) => row.repo_label || reviewRiskRepoLabel(row)))).sort((a, b) => a.localeCompare(b));
  const laneCounts = new Map(lanes.map((lane) => [lane, rows.filter((row) => (row.repo_label || reviewRiskRepoLabel(row)) === lane).length]));
  const maxLaneRows = Math.max(1, ...laneCounts.values());
  const laneHeight = lanes.length > 10 ? 33 : Math.max(38, Math.min(52, 26 + Math.sqrt(maxLaneRows) * 6));
  const width = Math.max(940, node.clientWidth || 940);
  const height = Math.max(290, 50 + lanes.length * laneHeight);
  const margin = { top: 22, right: 32, bottom: 36, left: 118 };
  const dotRadius = 12;
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const scoreValues = rows.map((row) => Number(row.scenario_score || 0)).filter((value) => Number.isFinite(value));
  let minScore = Math.min(...scoreValues);
  let maxScore = Math.max(...scoreValues);
  if (!Number.isFinite(minScore) || !Number.isFinite(maxScore)) {
    minScore = 0;
    maxScore = 100;
  } else if (minScore === maxScore) {
    minScore = Math.max(0, minScore - 1);
    maxScore = Math.min(100, maxScore + 1);
  } else {
    const scoreSpan = maxScore - minScore;
    const leftPad = Math.max(2, scoreSpan * 0.07);
    const rightPad = Math.max(1, scoreSpan * 0.03);
    minScore = Math.max(0, minScore - leftPad);
    maxScore = Math.min(100, maxScore + rightPad);
  }
  const x = d3lib.scaleLinear().domain([minScore, maxScore]).range([margin.left, width - margin.right]);
  const xTickValues = Array.from(new Set([minScore, ...x.ticks(4), maxScore]
    .filter((value) => value >= minScore && value <= maxScore)
    .map((value) => roundNumber(value, 1))));
  const y = d3lib.scaleBand().domain(lanes).range([margin.top, height - margin.bottom]).paddingInner(0.28).paddingOuter(0.15);
  const positioned = reviewRiskBeeswarmPositions(rows, lanes, x, y, dotRadius);
  const arc = d3lib.arc().innerRadius(0).outerRadius(dotRadius);
  const pie = d3lib.pie().value((item) => item.value).sort(null);

  svg.append("g")
    .attr("class", "decision-grid")
    .selectAll("line")
    .data(xTickValues)
    .join("line")
    .attr("x1", (tick) => x(tick))
    .attr("x2", (tick) => x(tick))
    .attr("y1", margin.top)
    .attr("y2", height - margin.bottom)
    .attr("stroke", "#e4e9f0");

  svg.append("g")
    .selectAll("line.repo-lane")
    .data(lanes)
    .join("line")
    .attr("class", "repo-lane")
    .attr("x1", margin.left)
    .attr("x2", width - margin.right)
    .attr("y1", (lane) => (y(lane) || 0) + y.bandwidth() / 2)
    .attr("y2", (lane) => (y(lane) || 0) + y.bandwidth() / 2)
    .attr("stroke", "#eef2f6");

  svg.append("g")
    .attr("transform", `translate(${margin.left},0)`)
    .call(d3lib.axisLeft(y).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 12).attr("fill", "#344054").attr("font-weight", 700));

  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(x).tickValues(xTickValues))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));

  svg.append("text")
    .attr("x", width - margin.right)
    .attr("y", height - 10)
    .attr("text-anchor", "end")
    .attr("font-size", 11)
    .attr("fill", "#667085")
    .text("scenario weighted risk score");

  const dots = svg.append("g")
    .selectAll("g.review-risk-decision-dot")
    .data(positioned)
    .join("g")
    .attr("class", "review-risk-decision-dot")
    .attr("data-review-risk-decision-dot", "1")
    .attr("data-change-number", (item) => item.row.change_number || "")
    .attr("transform", (item) => `translate(${item.x},${item.y})`)
    .attr("tabindex", 0)
    .attr("role", "button");

  dots.selectAll("path")
    .data((item) => pie(reviewRiskPieSegments(item.row.scenario_contributors)).map((slice) => ({ ...slice, row: item.row })))
    .join("path")
    .attr("d", arc)
    .attr("fill", (slice) => slice.data.color)
    .attr("stroke", "#fff")
    .attr("stroke-width", 0.7);

  dots.append("circle")
    .attr("r", dotRadius + 1.8)
    .attr("fill", "none")
    .attr("stroke", (item) => String(item.row.change_number) === String(state.selected.reviewRiskChangeNumber) ? "#101828" : "#344054")
    .attr("stroke-width", (item) => String(item.row.change_number) === String(state.selected.reviewRiskChangeNumber) ? 2.4 : 0.6)
    .attr("opacity", (item) => String(item.row.change_number) === String(state.selected.reviewRiskChangeNumber) ? 1 : 0.55);

  dots.append("title")
    .text((item) => reviewRiskDecisionTooltip(item.row));

  drawLegend(
    svg,
    reviewRiskDecisionSignals.slice(0, 6).map((signal) => ({ label: signal.label.replace(" Competence", "").replace("Review ", ""), color: signal.color })),
    margin.left,
    10,
  );
}

function reviewRiskBeeswarmPositions(rows, lanes, x, y, radius) {
  const minDistance = radius * 2 + 3;
  const step = radius + 3;
  const byLane = new Map(lanes.map((lane) => [lane, []]));
  for (const row of rows) {
    const lane = row.repo_label || reviewRiskRepoLabel(row);
    if (!byLane.has(lane)) byLane.set(lane, []);
    byLane.get(lane).push(row);
  }
  const positioned = [];
  for (const lane of lanes) {
    const center = (y(lane) || 0) + y.bandwidth() / 2;
    const halfBand = Math.max(radius, y.bandwidth() / 2 - radius - 2);
    const placed = [];
    const laneRows = (byLane.get(lane) || []).sort((a, b) => a.scenario_score - b.scenario_score || String(a.change_number).localeCompare(String(b.change_number)));
    for (const row of laneRows) {
      const px = x(row.scenario_score || 0);
      let chosen = 0;
      const offsets = [0];
      const maxSteps = Math.max(1, Math.floor(halfBand / step));
      for (let index = 1; index <= maxSteps; index += 1) offsets.push(-index * step, index * step);
      for (const offset of offsets) {
        const py = center + offset;
        const collides = placed.some((point) => {
          const dx = px - point.x;
          const dy = py - point.y;
          return Math.sqrt(dx * dx + dy * dy) < minDistance;
        });
        if (!collides) {
          chosen = offset;
          break;
        }
      }
      const point = { row, x: px, y: center + chosen };
      placed.push(point);
      positioned.push(point);
    }
  }
  return positioned;
}

function reviewRiskPieSegments(contributors = []) {
  const positive = contributors.filter((item) => item.weighted_value > 0).sort((a, b) => b.weighted_value - a.weighted_value);
  if (!positive.length) return [];
  const first = positive[0];
  const second = positive[1];
  const third = positive[2];
  const segments = [first, second].filter(Boolean).map((item) => ({
    label: item.label,
    color: item.color,
    value: item.weighted_value,
    percent: item.percent,
  }));
  if (third && third.percent >= 20) {
    segments.push({ label: third.label, color: third.color, value: third.weighted_value, percent: third.percent });
  }
  return segments;
}

function reviewRiskDecisionTooltip(row) {
  const contributors = reviewRiskPieSegments(row.scenario_contributors)
    .map((item) => `${item.label}: ${item.percent || 0}%`)
    .join(" | ");
  return [
    `Review ${row.change_number}`,
    row.subject,
    `repo: ${row.repo_label || reviewRiskRepoLabel(row)}`,
    `scenario score: ${row.scenario_score}`,
    `baseline bucket: ${formatNumber(row.bucket_score || 0)}`,
    `priority lane: ${row.priority_lane || ""}`,
    contributors,
  ].filter(Boolean).join("\n");
}

function renderReviewRiskDecisionSummary(rows = []) {
  const node = $("#reviewRiskDecisionSummary");
  if (!node) return;
  const row = rows.find((item) => String(item.change_number) === String(state.selected.reviewRiskChangeNumber)) || rows[0];
  if (!row) {
    node.innerHTML = `<div class="empty">Select a review dot to see author, reviewer, friction, and churn evidence.</div>`;
    return;
  }
  state.selected.reviewRiskChangeNumber = String(row.change_number || "");
  const authorName = row.owner || row.author_matched_git_name || row.author_email || row.owner_account_id || "unknown";
  const authorSurvival = row.author_line_survival_rate ? formatPercent(row.author_line_survival_rate) : "unknown";
  const authoredGitCommits = Number(row.author_authored_git_commits || 0);
  const authoredGitLines = Number(row.author_authored_git_changed_lines || 0);
  const commitHistory = [
    `${formatNumber(authoredGitCommits)} git`,
    `${formatCompactNumber(authoredGitLines)} LOC`,
    row.author_authored_reviews_count ? `${formatNumber(row.author_authored_reviews_count)} rev` : null,
    row.author_commits_analyzed ? `${formatNumber(row.author_commits_analyzed)} LS` : null,
  ].filter(Boolean).join(" / ") || "thin or missing history";
  const contradictedVotes = Math.min(Number(row.positive_votes || 0), Number(row.negative_votes || 0));
  const reviewHref = row.review_url ? escapeAttr(row.review_url) : "";
  const titleText = row.subject || "";
  const titleHtml = reviewHref
    ? `<a class="decision-summary-title-link" href="${reviewHref}" target="_blank" rel="noreferrer">Title: ${escapeHtml(titleText)}</a>`
    : `<span class="decision-summary-title-text">Title: ${escapeHtml(titleText)}</span>`;
  const contributors = reviewRiskSummaryContributors(row);
  node.innerHTML = `
    <div class="decision-summary-head">
      <div>
        <div class="decision-summary-review-line">
          <strong>Review ${escapeHtml(row.change_number || "")}</strong>
          <span>${contributors}</span>
        </div>
        <div class="decision-summary-title-row">
          ${titleHtml}
          <span>/ Status: ${escapeHtml(row.status || "unknown")} / Created: ${escapeHtml(formatDateTimeCompact(row.created_at))} / Updated: ${escapeHtml(formatDateTimeCompact(row.updated_at))}</span>
        </div>
      </div>
      <div class="decision-summary-scores">
        <span>scenario ${escapeHtml(formatNumber(row.scenario_score || 0))}</span>
        <span>bucket ${escapeHtml(formatNumber(row.bucket_score || 0))}</span>
        <span>${escapeHtml(row.priority_lane || row.risk_level || "watch")}</span>
      </div>
    </div>
    <div class="decision-summary-grid">
      ${decisionSummaryBlock("Author", [
        ["author", authorName],
        ["survival", authorSurvival],
        ["history", commitHistory],
      ])}
      ${decisionSummaryBlock("Reviewers", [
        ["reviewer names", row.reviewers || "unknown"],
        ["survival", row.reviewer_avg_line_survival_rate ? formatPercent(row.reviewer_avg_line_survival_rate) : "unknown"],
        ["competence risk", `${formatNumber(row.reviewer_score || 0)} from ${formatNumber(row.reviewer_history_count || 0)} history rows`],
      ])}
      ${decisionSummaryBlock("Review Friction", [
        ["unresolved", formatNumber(row.unresolved_comments || 0)],
        ["negative votes", formatNumber(row.negative_votes || 0)],
        ["contradicted", formatNumber(contradictedVotes)],
      ])}
      ${decisionSummaryBlock("Review Churn", [
        ["patch sets", formatNumber(row.patch_sets || 0)],
        ["rework score", formatNumber(row.rework_score || 0)],
        ["changed lines", formatNumber(row.changed_lines || 0)],
      ])}
    </div>
  `;
}

function reviewRiskSummaryContributors(row) {
  const contributors = (row.scenario_contributors || [])
    .filter((item) => Number(item.weighted_value || 0) > 0)
    .sort((a, b) => Number(b.weighted_value || 0) - Number(a.weighted_value || 0))
    .slice(0, 4)
    .map((item) => `${reviewRiskShortSignalLabels[item.id] || item.label || item.id} (${Math.round(Number(item.percent || 0))}%)`);
  return contributors.length ? escapeHtml(contributors.join("  ")) : "";
}

function decisionSummaryBlock(title, rows) {
  return `
    <div class="decision-summary-block">
      <h4>${escapeHtml(title)}</h4>
      ${rows.map(([label, value]) => `
        <div class="decision-summary-row">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>
      `).join("")}
    </div>
  `;
}

function reviewRiskColumns() {
  return [
    {
      key: "review",
      label: "Review",
      description: "Gerrit review number, subject, project, and status. Click the row to inspect all fields.",
      render: (row) => {
        const review = row.review_url
          ? `<a href="${escapeAttr(row.review_url)}" target="_blank" rel="noreferrer">${escapeHtml(row.change_number)}</a>`
          : escapeHtml(row.change_number);
        return `
          <div class="review-risk-review-cell">
            <strong>${review}</strong>
            <span>${escapeHtml(row.subject || "")}</span>
            <small>${escapeHtml([row.project, row.branch, row.status].filter(Boolean).join(" | "))}</small>
          </div>
        `;
      },
    },
    {
      key: "score",
      label: "Priority",
      description: "Mission priority score. Security relevance opens the gate; author competence, reviewer competence, churn, and comment smell decide ranking inside that gate.",
      render: (row) => `
        <button
          class="score-breakdown-button"
          data-review-risk-contributors="1"
          data-change-number="${escapeAttr(row.change_number || "")}"
          title="Show score contributors"
        >${escapeHtml(formatCell(row.risk_score))}</button>
        <div class="mini">${escapeHtml(row.priority_lane || row.risk_level || "")}</div>
      `,
    },
    {
      key: "author",
      label: "Author",
      description: "Commit author competence. Higher competence is better; the small number is the risk points added for low or unknown author competence.",
      render: (row) => `
        <strong>${escapeHtml(row.author_competence_score == null ? "unknown" : formatNumber(row.author_competence_score))}</strong>
        <div class="mini">+${escapeHtml(formatNumber(row.author_score || 0))} risk | ${escapeHtml(formatPercent(row.author_competence_confidence || 0))} conf</div>
      `,
    },
    {
      key: "security",
      label: "Locus",
      description: "Broad security locus used as a gate, not as the whole ranking. Examples: critical, important, process-only, suppressed mechanical.",
      render: (row) => `
        <strong>${escapeHtml(row.security_locus || "watch")}</strong>
        <div class="mini">${escapeHtml(formatCell(row.security_score))} security | ${escapeHtml(row.change_shape || "")}</div>
      `,
    },
    {
      key: "implementation",
      label: "Impl",
      description: "Implementation risk score from concern density, repeated file concerns, author response ratio, reviewer spread after first concern, patch-set churn after first concern, and small-change high-friction.",
      render: (row) => `
        <strong>${escapeHtml(formatCell(row.implementation_score))}</strong>
        <div class="mini">${escapeHtml(formatCell(row.implementation_concern_messages))} concerns | ${escapeHtml(formatCell(row.implementation_signal_score))} signals</div>
      `,
    },
    {
      key: "reviewer",
      label: "Reviewer",
      description: "Reviewer survival score. Uses current approval line survival when available, otherwise reviewer historical line survival.",
      render: (row) => `
        <strong>${escapeHtml(formatCell(row.reviewer_score))}</strong>
        <div class="mini">${escapeHtml(formatCell(row.approval_survival_approvals))} approval rows | ${escapeHtml(formatPercent(row.reviewer_avg_line_survival_rate))} history</div>
      `,
    },
    {
      key: "reasons",
      label: "Reasons",
      description: "Highest-signal reasons that explain why this review ranked where it did. Use messages for scored review-message text.",
      render: (row) => {
        const reasonsText = (row.risk_reasons || []).join(" | ") || `${formatCell(row.sensitivity_ge40_messages)} scored messages`;
        return `
          <div class="reason-stack">
            <button
              class="reason-button"
              data-review-risk-contributors="1"
              data-change-number="${escapeAttr(row.change_number || "")}"
              title="Show score contributors"
            >${escapeHtml(reasonsText)}</button>
            <button
              class="mini-link-button"
              data-review-risk-messages="1"
              data-change-number="${escapeAttr(row.change_number || "")}"
              data-project="${escapeAttr(row.project || "")}"
              data-repository-id="${escapeAttr(row.repository_id || "")}"
              title="Show all review messages with score >= 40"
            >messages</button>
          </div>
        `;
      },
    },
  ];
}

function reviewRiskColumnMap() {
  return new Map(reviewRiskColumns().map((column) => [column.key, column]));
}

function renderReviewRiskTable(selector, rows) {
  const node = $(selector);
  if (!node) return;
  const columns = reviewRiskColumns();
  const selected = state.selected.reviewRiskChangeNumber || rows?.[0]?.change_number || "";
  if (selected) state.selected.reviewRiskChangeNumber = String(selected);
  node.innerHTML = `
    <table class="review-risk-compact-table">
      <thead>
        <tr>
          ${columns.map((column) => `
            <th>
              <button
                class="column-help-button"
                data-review-risk-header="${escapeAttr(column.key)}"
                title="${escapeAttr(column.description)}"
              >${escapeHtml(column.label)}</button>
            </th>
          `).join("")}
        </tr>
      </thead>
      <tbody>
        ${(rows || []).map((row) => {
          const isSelected = String(row.change_number) === String(selected);
          return `
            <tr
              class="${isSelected ? "selected" : ""}"
              data-review-risk-row="1"
              data-change-number="${escapeAttr(row.change_number || "")}"
              title="Click to show full row details below"
            >
              ${columns.map((column) => `<td>${column.render(row)}</td>`).join("")}
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
  renderReviewRiskSelectedDetail(rows);
}

function selectReviewRiskRow(changeNumber) {
  if (!changeNumber) return;
  state.selected.reviewRiskChangeNumber = String(changeNumber);
  const scenario = state.data.reviewRiskDecisionScenario || reviewRiskDecisionScenario(state.data.reviewRisk?.proposed_review_risk || []);
  drawReviewRiskDecisionGraph("#reviewRiskDecisionGraph", scenario.filteredRows || []);
  renderReviewRiskDecisionSummary(scenario.filteredRows || []);
  renderReviewRiskTable("#reviewRiskTable", scenario.filteredRows || []);
}

function renderReviewRiskSelectedDetail(rows = []) {
  const node = $("#reviewRiskSelectedDetail");
  if (!node) return;
  const selectedId = state.selected.reviewRiskChangeNumber || rows?.[0]?.change_number || "";
  const row = (rows || []).find((item) => String(item.change_number) === String(selectedId)) || rows?.[0];
  if (!row) {
    node.innerHTML = `<div class="empty">Select a review row to see all details.</div>`;
    return;
  }
  state.selected.reviewRiskChangeNumber = String(row.change_number || "");
  const scalarRows = reviewRiskDetailFields(row);
  node.innerHTML = `
    <div class="review-risk-detail-head">
      <div>
        <h4>Review ${escapeHtml(row.change_number || "")}</h4>
        <p>${escapeHtml(row.subject || "")}</p>
      </div>
      <div class="review-risk-detail-actions">
        ${row.review_url ? `<a href="${escapeAttr(row.review_url)}" target="_blank" rel="noreferrer">open review</a>` : ""}
        <button
          class="mini-link-button"
          data-review-risk-contributors="1"
          data-change-number="${escapeAttr(row.change_number || "")}"
        >score breakdown</button>
        <button
          class="mini-link-button"
          data-review-risk-messages="1"
          data-change-number="${escapeAttr(row.change_number || "")}"
          data-project="${escapeAttr(row.project || "")}"
          data-repository-id="${escapeAttr(row.repository_id || "")}"
        >messages</button>
      </div>
    </div>
    <div class="review-risk-detail-grid">
      ${scalarRows.map((field) => `
        <div class="review-risk-detail-item">
          <button
            class="detail-help-button"
            data-review-risk-detail-field="${escapeAttr(field.key)}"
            title="${escapeAttr(field.description)}"
          >${escapeHtml(field.label)}</button>
          <strong>${escapeHtml(field.value)}</strong>
        </div>
      `).join("")}
    </div>
    <div class="score-breakdown-grid review-risk-inline-breakdown">
      ${(row.score_contributors || []).map(renderScoreContributorBucket).join("")}
    </div>
    <div class="score-breakdown-two">
      ${renderSurvivalTable("Current Approval Survival", row.approval_survival_reviewers || [], [
        ["Reviewer", (item) => item.reviewer],
        ["Survival", (item) => formatPercent(item.line_survival_rate)],
        ["Tracked", (item) => item.insertions_tracked],
        ["Surviving", (item) => item.surviving_lines],
        ["Overwritten", (item) => item.cross_author_overwritten_lines],
        ["Labels", (item) => (item.labels || []).join(", ")],
      ])}
      ${renderSurvivalTable("Reviewer History", row.reviewer_history || [], [
        ["Reviewer", (item) => item.reviewer],
        ["Survival", (item) => formatPercent(item.line_survival_rate)],
        ["Reviews", (item) => item.reviewed_changes_count],
        ["Approvals", (item) => item.approvals_count],
        ["Tracked", (item) => item.insertions_tracked],
        ["Surviving", (item) => item.surviving_lines],
      ])}
    </div>
    <details class="review-risk-json-detail">
      <summary>Full row JSON</summary>
      <pre>${escapeHtml(JSON.stringify(row, null, 2))}</pre>
    </details>
  `;
}

function reviewRiskDetailFields(row) {
  return reviewRiskDetailFieldDefinitions().map((field) => ({
    ...field,
    value: String(field.value(row) ?? ""),
  }));
}

function reviewRiskDetailFieldMap() {
  return new Map(reviewRiskDetailFieldDefinitions().map((field) => [field.key, field]));
}

function reviewRiskDetailFieldDefinitions() {
  return [
    {
      key: "risk_score",
      label: "Mission priority",
      description: "Primary ranking score. Security relevance gates the review, then author competence, reviewer competence, churn, and comment smell decide priority.",
      value: (row) => formatNumber(row.risk_score),
    },
    {
      key: "priority_lane",
      label: "Priority lane",
      description: "Decision-tree lane for this review, such as urgent compute, high compute, routine security-relevant, process smell, or suppressed mechanical.",
      value: (row) => row.priority_lane || "",
    },
    {
      key: "security_locus",
      label: "Security locus",
      description: "Broad security-relevance bucket used as a gate, not as a verdict.",
      value: (row) => row.security_locus || "",
    },
    {
      key: "change_shape",
      label: "Change shape",
      description: "Review shape from persisted file/change evidence, such as runtime code, test-only, merge-only, CI-only, or observability-only.",
      value: (row) => row.change_shape || "",
    },
    {
      key: "flat_risk_score",
      label: "Legacy flat score",
      description: "Previous blended score before mission-priority lane sorting. Kept for comparison while tuning.",
      value: (row) => formatNumber(row.flat_risk_score || 0),
    },
    {
      key: "author_competence_score",
      label: "Author competence",
      description: "0-100 score for the review author using confidence-weighted code survival, rework, authored review history, review friction, and implementation-risk history. Higher is better.",
      value: (row) => row.author_competence_score == null ? "unknown" : formatNumber(row.author_competence_score),
    },
    {
      key: "author_score",
      label: "Author risk",
      description: "Risk points added because author competence is low or uncertain.",
      value: (row) => formatNumber(row.author_score || 0),
    },
    {
      key: "author_competence_confidence",
      label: "Author confidence",
      description: "How much evidence supports the author competence score. Combines Git code evidence and Gerrit review-history evidence.",
      value: (row) => formatPercent(row.author_competence_confidence || 0),
    },
    {
      key: "author_code_confidence",
      label: "Code evidence confidence",
      description: "Confidence from small-commit line survival: more analyzed commits and tracked inserted lines increases confidence.",
      value: (row) => formatPercent(row.author_code_confidence || 0),
    },
    {
      key: "author_review_confidence",
      label: "Review history confidence",
      description: "Confidence from historical authored Gerrit reviews in this repository/project.",
      value: (row) => formatPercent(row.author_review_confidence || 0),
    },
    {
      key: "author_experience_confidence",
      label: "Author experience confidence",
      description: "Confidence from authored git commit count, changed lines, and authored reviews when line-survival analysis has few commits.",
      value: (row) => formatPercent(row.author_experience_confidence || 0),
    },
    {
      key: "author_experience_score",
      label: "Author experience score",
      description: "Experience score derived from authored git commits, authored changed lines, and authored Gerrit reviews. Higher is better.",
      value: (row) => formatNumber(row.author_experience_score || 0),
    },
    {
      key: "author_authored_git_commits",
      label: "Author git commits",
      description: "Primary-authored git commits matched to this author in the scoped repository.",
      value: (row) => formatNumber(row.author_authored_git_commits || 0),
    },
    {
      key: "author_authored_git_changed_lines",
      label: "Author git changed lines",
      description: "Total inserted plus deleted lines across matched primary-authored git commits in the scoped repository.",
      value: (row) => formatNumber(row.author_authored_git_changed_lines || 0),
    },
    {
      key: "author_authored_reviews_count",
      label: "Author reviews",
      description: "Number of Gerrit reviews authored by this owner in the scoped repository/project.",
      value: (row) => formatNumber(row.author_authored_reviews_count || 0),
    },
    {
      key: "author_merged_reviews_count",
      label: "Author merged reviews",
      description: "Historical authored reviews that merged.",
      value: (row) => formatNumber(row.author_merged_reviews_count || 0),
    },
    {
      key: "author_abandoned_reviews_count",
      label: "Author abandoned reviews",
      description: "Historical authored reviews that were abandoned.",
      value: (row) => formatNumber(row.author_abandoned_reviews_count || 0),
    },
    {
      key: "author_avg_implementation_signal_score",
      label: "Author avg impl risk",
      description: "Average historical implementation-risk signal score across this author's reviews.",
      value: (row) => formatNumber(row.author_avg_implementation_signal_score || 0),
    },
    {
      key: "author_avg_patch_sets",
      label: "Author avg patch sets",
      description: "Average patch-set count on this author's historical reviews.",
      value: (row) => formatNumber(row.author_avg_patch_sets || 0),
    },
    {
      key: "author_avg_unresolved_comments",
      label: "Author avg unresolved",
      description: "Average unresolved comment count on this author's historical reviews.",
      value: (row) => formatNumber(row.author_avg_unresolved_comments || 0),
    },
    {
      key: "author_high_implementation_reviews",
      label: "Author high-risk reviews",
      description: "Historical authored reviews with high implementation-risk signals.",
      value: (row) => formatNumber(row.author_high_implementation_reviews || 0),
    },
    {
      key: "author_line_survival_rate",
      label: "Author survival",
      description: "Share of the author's tracked inserted lines that still survive in the analyzed branch.",
      value: (row) => formatPercent(row.author_line_survival_rate),
    },
    {
      key: "author_commits_analyzed",
      label: "Author commits analyzed",
      description: "Number of small commits included in the author's line-survival analysis.",
      value: (row) => formatNumber(row.author_commits_analyzed || 0),
    },
    {
      key: "security_score",
      label: "Security score",
      description: "Risk points from ONNX sensitivity, keyword rules, security-sensitive files, attack-surface files, dependency files, and workflow files.",
      value: (row) => formatNumber(row.security_score),
    },
    {
      key: "implementation_score",
      label: "Implementation risk",
      description: "Risk points from review signals that suggest the implementation may be weak: concern density, repeated file concerns, author responses, reviewer spread, patch-set churn after concerns, and small-change friction.",
      value: (row) => formatNumber(row.implementation_score || 0),
    },
    {
      key: "implementation_signal_score",
      label: "Implementation signals",
      description: "Count of implementation-risk signal thresholds hit for this review.",
      value: (row) => formatNumber(row.implementation_signal_score || 0),
    },
    {
      key: "implementation_concern_messages",
      label: "Concern messages",
      description: "Human reviewer messages that look like implementation concerns rather than automation or simple status updates.",
      value: (row) => formatNumber(row.implementation_concern_messages || 0),
    },
    {
      key: "implementation_concern_density_per_touched_file",
      label: "Concern density/file",
      description: "Concern messages divided by touched files. Higher means reviewers concentrated concern on a smaller code surface.",
      value: (row) => formatCell(row.implementation_concern_density_per_touched_file || 0),
    },
    {
      key: "implementation_repeated_concern_file_count",
      label: "Repeated concern files",
      description: "Touched files that received at least two concern messages.",
      value: (row) => formatNumber(row.implementation_repeated_concern_file_count || 0),
    },
    {
      key: "implementation_author_response_ratio",
      label: "Author response ratio",
      description: "Owner response messages after the first concern divided by concern messages.",
      value: (row) => formatPercent(row.implementation_author_response_ratio || 0),
    },
    {
      key: "implementation_reviewer_spread_after_first_concern",
      label: "Reviewers after concern",
      description: "Distinct human reviewers participating after the first concern appeared.",
      value: (row) => formatNumber(row.implementation_reviewer_spread_after_first_concern || 0),
    },
    {
      key: "implementation_patch_sets_after_first_concern",
      label: "Patch sets after concern",
      description: "Patch-set churn after the first concern appeared.",
      value: (row) => formatNumber(row.implementation_patch_sets_after_first_concern || 0),
    },
    {
      key: "implementation_distinct_concern_patch_sets",
      label: "Concern patch sets",
      description: "Number of distinct patch sets that had human concern messages.",
      value: (row) => formatNumber(row.implementation_distinct_concern_patch_sets || 0),
    },
    {
      key: "implementation_concern_span_patch_sets",
      label: "Concern span",
      description: "How far concerns persisted across patch sets, measured from first concern patch set to last concern patch set.",
      value: (row) => formatNumber(row.implementation_concern_span_patch_sets || 0),
    },
    {
      key: "implementation_concerns_after_positive_vote",
      label: "Concerns after approval",
      description: "Concern messages on or after the first positive review vote. This catches approvals that did not settle the review.",
      value: (row) => formatNumber(row.implementation_concerns_after_positive_vote || 0),
    },
    {
      key: "implementation_security_sensitive_repeated_concern_file_count",
      label: "Sensitive repeated concerns",
      description: "Security-sensitive files that received repeated concern messages.",
      value: (row) => formatNumber(row.implementation_security_sensitive_repeated_concern_file_count || 0),
    },
    {
      key: "implementation_small_change_high_friction",
      label: "Small high-friction",
      description: "True when a change has 100 or fewer changed lines but still has concentrated review friction.",
      value: (row) => row.implementation_small_change_high_friction ? "yes" : "no",
    },
    {
      key: "sensitivity_ge40_messages",
      label: "ONNX >=40",
      description: "Number of human review messages with ONNX sensitivity score at least 40.",
      value: (row) => formatNumber(row.sensitivity_ge40_messages || 0),
    },
    {
      key: "security_signal_mentions",
      label: "Keyword hits",
      description: "Number of human review messages matching configured security-sensitive keyword rules.",
      value: (row) => formatNumber(row.security_signal_mentions || 0),
    },
    {
      key: "reviewer_score",
      label: "Reviewer score",
      description: "Risk points from current approval survival when present, otherwise reviewer historical line survival.",
      value: (row) => formatNumber(row.reviewer_score),
    },
    {
      key: "reviewer_avg_line_survival_rate",
      label: "Reviewer history avg",
      description: "Average line survival for the reviewers on this change, using their historical approval survival metadata.",
      value: (row) => formatPercent(row.reviewer_avg_line_survival_rate),
    },
    {
      key: "friction_score",
      label: "Friction score",
      description: "Risk points from unresolved comments, negative votes, contradictory votes, and comment volume.",
      value: (row) => formatNumber(row.friction_score),
    },
    {
      key: "unresolved_comments",
      label: "Unresolved comments",
      description: "Open review comments in Gerrit. Higher values indicate unresolved concerns.",
      value: (row) => formatNumber(row.unresolved_comments || 0),
    },
    {
      key: "negative_votes",
      label: "Negative votes",
      description: "Count of negative review vote metadata found for this change.",
      value: (row) => formatNumber(row.negative_votes || 0),
    },
    {
      key: "rework_score",
      label: "Rework score",
      description: "Risk points from patch-set count, touched files, changed lines, and human reviewer count.",
      value: (row) => formatNumber(row.rework_score),
    },
    {
      key: "patch_sets",
      label: "Patch sets",
      description: "Number of patch sets observed for the review. More patch sets often means more churn or difficulty.",
      value: (row) => formatNumber(row.patch_sets || 0),
    },
    {
      key: "changed_lines",
      label: "Changed lines",
      description: "Insertions plus deletions reported by Gerrit for this review.",
      value: (row) => formatNumber(row.changed_lines || 0),
    },
    {
      key: "stale_score",
      label: "Stale score",
      description: "Risk points for long-open NEW reviews. Merged and abandoned reviews do not get stale points.",
      value: (row) => formatNumber(row.stale_score),
    },
    {
      key: "risk_level",
      label: "Risk level",
      description: "Text bucket derived from the total risk score.",
      value: (row) => row.risk_level || "",
    },
    {
      key: "owner",
      label: "Owner",
      description: "Gerrit owner of the review. This is treated as the proposed change author for this page.",
      value: (row) => row.owner || "",
    },
    {
      key: "author_email",
      label: "Author email",
      description: "Git author email used to find line-survival metadata for the Gerrit owner.",
      value: (row) => row.author_email || "",
    },
    {
      key: "author_cross_author_overwrite_rate",
      label: "Author overwrite rate",
      description: "Share of the author's tracked inserted lines later overwritten by other authors.",
      value: (row) => formatPercent(row.author_cross_author_overwrite_rate),
    },
    {
      key: "author_self_rework_rate",
      label: "Author self-rework rate",
      description: "Share of the author's tracked inserted lines later rewritten by the same author.",
      value: (row) => formatPercent(row.author_self_rework_rate),
    },
    {
      key: "author_insertions_tracked",
      label: "Author tracked lines",
      description: "Inserted lines included in the author's line-survival analysis.",
      value: (row) => formatNumber(row.author_insertions_tracked || 0),
    },
    {
      key: "author_surviving_lines",
      label: "Author surviving lines",
      description: "Tracked inserted lines by this author still present in the analyzed branch.",
      value: (row) => formatNumber(row.author_surviving_lines || 0),
    },
    {
      key: "max_sensitivity_score",
      label: "ONNX max",
      description: "Highest ONNX sensitivity score among the review's messages.",
      value: (row) => formatCell(row.max_sensitivity_score),
    },
    {
      key: "keyword_score",
      label: "Keyword score",
      description: "Weighted score from configured security keyword rules. The main score caps this contribution.",
      value: (row) => formatNumber(row.keyword_weighted_score || 0),
    },
    {
      key: "keyword_rules",
      label: "Keyword rules",
      description: "Distinct keyword rule categories matched by this review's messages.",
      value: (row) => (row.keyword_hits || []).map((hit) => hit.label || hit.id).join(", "),
    },
    {
      key: "security_sensitive_files",
      label: "Sensitive files",
      description: "Count of touched files classified as security-sensitive.",
      value: (row) => formatNumber(row.security_sensitive_files || 0),
    },
    {
      key: "attack_surface_files",
      label: "Attack-surface files",
      description: "Count of touched files classified as attack-surface related.",
      value: (row) => formatNumber(row.attack_surface_files || 0),
    },
    {
      key: "dependency_files",
      label: "Dependency files",
      description: "Count of touched dependency manifest or packaging files.",
      value: (row) => formatNumber(row.dependency_files || 0),
    },
    {
      key: "workflow_files",
      label: "Workflow files",
      description: "Count of touched CI/workflow files.",
      value: (row) => formatNumber(row.workflow_files || 0),
    },
    {
      key: "review_messages",
      label: "Review messages",
      description: "Total normalized code-review message arts for this change.",
      value: (row) => formatNumber(row.review_messages || 0),
    },
    {
      key: "human_reviewers",
      label: "Human reviewers",
      description: "Distinct non-automated reviewers/commenters on this change.",
      value: (row) => formatNumber(row.human_reviewers || 0),
    },
    {
      key: "reviewers",
      label: "Reviewers",
      description: "Names of human reviewers/commenters seen in the normalized review messages.",
      value: (row) => row.reviewers || "",
    },
    {
      key: "approval_survival_approvals",
      label: "Approval survival rows",
      description: "Current-review approval survival rows found for this change.",
      value: (row) => formatNumber(row.approval_survival_approvals || 0),
    },
    {
      key: "approval_line_survival_rate",
      label: "Approval survival avg",
      description: "Average line survival for approvals on this current review when direct approval survival data exists.",
      value: (row) => formatPercent(row.approval_line_survival_rate),
    },
    {
      key: "reviewer_history_count",
      label: "Reviewer history rows",
      description: "Number of reviewers with historical approval-survival metadata.",
      value: (row) => formatNumber(row.reviewer_history_count || 0),
    },
    {
      key: "project",
      label: "Project",
      description: "Gerrit project for this review.",
      value: (row) => row.project || "",
    },
    {
      key: "branch",
      label: "Branch",
      description: "Target branch for this review.",
      value: (row) => row.branch || "",
    },
    {
      key: "status",
      label: "Status",
      description: "Gerrit status for this review.",
      value: (row) => row.status || "",
    },
    {
      key: "created_at",
      label: "Created",
      description: "Review creation timestamp from Gerrit.",
      value: (row) => row.created_at || "",
    },
    {
      key: "updated_at",
      label: "Updated",
      description: "Review update timestamp from Gerrit.",
      value: (row) => row.updated_at || "",
    },
    {
      key: "age_days",
      label: "Age",
      description: "Days since the review was created.",
      value: (row) => `${formatNumber(row.age_days || 0)} days`,
    },
    {
      key: "reasons",
      label: "Reasons",
      description: "Human-readable explanation snippets for the highest-signal contributors.",
      value: (row) => (row.risk_reasons || []).join(" | "),
    },
  ];
}

async function openReviewRiskMessages(changeNumber, project = "", repositoryId = "") {
  if (!changeNumber) return;
  state.reviewRiskMessageContext = { changeNumber, project, repositoryId };
  const modal = $("#reviewRiskMessageModal");
  const title = $("#reviewRiskMessageTitle");
  const subtitle = $("#reviewRiskMessageSubtitle");
  const body = $("#reviewRiskMessageBody");
  if (!modal || !title || !subtitle || !body) return;
  modal.hidden = false;
  title.textContent = `Review ${changeNumber}`;
  subtitle.textContent = "Loading ONNX-high and keyword-hit messages";
  body.innerHTML = `<div class="json-card">Loading...</div>`;
  const params = new URLSearchParams({
    change_number: changeNumber,
    min_score: "40",
  });
  if (project) params.set("project", project);
  if (repositoryId) params.set("repository_id", repositoryId);
  try {
    const value = await api("metadata", "GET", `/console/repointel-review-risk-messages?${params}`);
    title.textContent = `Review ${value.change_number || changeNumber}`;
    state.reviewRiskMessageContext = {
      changeNumber: value.change_number || changeNumber,
      project: value.project || project || "",
      repositoryId: value.keyword_repository_id || value.repository_id || repositoryId || "",
    };
    subtitle.textContent = `${value.project || project || "review"} | ${formatNumber(value.count || 0)} message(s), sorted by ONNX + keyword weight | keyword repo ${value.keyword_repository_id || value.repository_id || "global"}`;
    renderReviewRiskMessages(value);
  } catch (err) {
    subtitle.textContent = "Failed";
    body.innerHTML = `<div class="stat-card bad"><div class="value">ERR</div><div class="label">${escapeHtml(err.message)}</div></div>`;
    toast("Scored messages unavailable", true, err.message);
  }
}

function openReviewRiskContributors(changeNumber) {
  if (!changeNumber) return;
  const rows = state.data.reviewRisk?.proposed_review_risk || [];
  const row = rows.find((item) => String(item.change_number) === String(changeNumber));
  if (!row) {
    toast("Score breakdown unavailable", true, `Review ${changeNumber} is not in the current table`);
    return;
  }
  const modal = $("#reviewRiskMessageModal");
  const title = $("#reviewRiskMessageTitle");
  const subtitle = $("#reviewRiskMessageSubtitle");
  const body = $("#reviewRiskMessageBody");
  if (!modal || !title || !subtitle || !body) return;
  modal.hidden = false;
  title.textContent = `Review ${row.change_number}`;
  subtitle.textContent = `${row.project || "review"} | priority ${formatNumber(row.risk_score)} | ${row.priority_lane || "watch"} | ${row.security_locus || "locus unknown"} | legacy flat ${formatNumber(row.flat_risk_score || 0)}`;
  body.innerHTML = renderReviewRiskContributors(row);
}

function renderReviewRiskContributors(row) {
  const contributors = Array.isArray(row.score_contributors) ? row.score_contributors : [];
  const approvalReviewers = row.approval_survival_reviewers || [];
  const reviewerHistory = row.reviewer_history || [];
  const currentReviewLink = row.review_url
    ? `<a href="${escapeAttr(row.review_url)}" target="_blank" rel="noreferrer">open review</a>`
    : "";
  return `
    <div class="score-breakdown-summary">
      <div class="stat-card"><div class="value">${escapeHtml(formatNumber(row.risk_score))}</div><div class="label">Risk score</div></div>
      <div class="stat-card"><div class="value">${escapeHtml(row.risk_level || "")}</div><div class="label">Level</div></div>
      <div class="stat-card"><div class="value">${escapeHtml(formatNumber(row.insertions + row.deletions || 0))}</div><div class="label">Changed lines</div></div>
      <div class="stat-card"><div class="value">${escapeHtml(formatNumber(row.patch_sets || 0))}</div><div class="label">Patch sets</div></div>
    </div>
    <div class="score-breakdown-meta">
      <strong>${escapeHtml(row.subject || "")}</strong>
      <span>${escapeHtml(row.status || "")} ${currentReviewLink}</span>
    </div>
    <div class="score-breakdown-grid">
      ${contributors.map(renderScoreContributorBucket).join("")}
    </div>
    <div class="score-breakdown-two">
      ${renderSurvivalTable("Current Approval Survival", approvalReviewers, [
        ["Reviewer", (item) => item.reviewer],
        ["Survival", (item) => formatPercent(item.line_survival_rate)],
        ["Tracked", (item) => item.insertions_tracked],
        ["Surviving", (item) => item.surviving_lines],
        ["Overwritten", (item) => item.cross_author_overwritten_lines],
        ["Labels", (item) => (item.labels || []).join(", ")],
      ])}
      ${renderSurvivalTable("Reviewer History", reviewerHistory, [
        ["Reviewer", (item) => item.reviewer],
        ["Survival", (item) => formatPercent(item.line_survival_rate)],
        ["Reviews", (item) => item.reviewed_changes_count],
        ["Approvals", (item) => item.approvals_count],
        ["Tracked", (item) => item.insertions_tracked],
        ["Surviving", (item) => item.surviving_lines],
      ])}
    </div>
  `;
}

function renderScoreContributorBucket(bucket) {
  const items = Array.isArray(bucket.items) ? bucket.items : [];
  const nonZero = items.filter((item) => Number(item.value || 0) !== 0 || Number(item.points || 0) !== 0);
  return `
    <section class="score-breakdown-bucket">
      <div class="score-breakdown-bucket-head">
        <strong>${escapeHtml(bucket.bucket || "")}</strong>
        <span>${escapeHtml(formatNumber(bucket.points || 0))}</span>
      </div>
      <table>
        <thead><tr><th>Signal</th><th>Value</th><th>Points</th></tr></thead>
        <tbody>
          ${(nonZero.length ? nonZero : items).map((item) => `
            <tr>
              <td>${escapeHtml(item.label || "")}</td>
              <td>${escapeHtml(`${formatCell(item.value)}${item.unit || ""}`)}</td>
              <td>${escapeHtml(formatCell(item.points ?? ""))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </section>
  `;
}

function renderSurvivalTable(title, rows = [], columns = []) {
  return `
    <section class="survival-detail-table">
      <h4>${escapeHtml(title)}</h4>
      ${rows.length ? `
        <table>
          <thead><tr>${columns.map(([heading]) => `<th>${escapeHtml(heading)}</th>`).join("")}</tr></thead>
          <tbody>
            ${rows.map((row) => `
              <tr>${columns.map(([, getter]) => `<td>${escapeHtml(formatCell(getter(row)))}</td>`).join("")}</tr>
            `).join("")}
          </tbody>
        </table>
      ` : `<div class="mini">No rows for this review in the current data.</div>`}
    </section>
  `;
}

function renderReviewRiskMessages(value) {
  const body = $("#reviewRiskMessageBody");
  if (!body) return;
  const messages = value.messages || [];
  const keywordRules = normalizeKeywordRulesForUi(value.keyword_config?.rules || []);
  const keywordPanel = renderKeywordConfigPanel(value.keyword_repository_id || value.repository_id || "", keywordRules);
  if (!messages.length) {
    body.innerHTML = `
      ${keywordPanel}
      <div class="stat-card"><div class="value">0</div><div class="label">No messages scored >= ${escapeHtml(value.min_score || 40)} and no keyword-hit messages</div></div>
    `;
    return;
  }
  body.innerHTML = `
    ${keywordPanel}
    ${messages.map((message) => {
      const matchedRules = normalizeKeywordRulesForUi(message.keyword_matches || []);
      return `
      <article class="score-message">
        <div class="score-message-head">
          <div>
            <span class="score-message-score">Combined ${escapeHtml(formatCell(message.combined_score ?? message.score))}</span>
            <span class="score-pill">ONNX ${escapeHtml(formatCell(message.score))}</span>
            <span class="score-pill">Keyword +${escapeHtml(formatCell(message.keyword_weight_sum || 0))}</span>
            <span>${escapeHtml(message.label || "")}</span>
            ${message.keyword_hit ? `<span class="score-message-keyword">keyword</span>` : ""}
            <span>${escapeHtml(message.author || message.author_id || "")}</span>
            ${message.patch_set ? `<span>PS ${escapeHtml(message.patch_set)}</span>` : ""}
          </div>
          <div>${escapeHtml((message.created_at || "").replace(/^unix:/, ""))}</div>
        </div>
        ${matchedRules.length ? `<div class="score-message-keywords">${matchedRules.map(keywordChip).join("")}</div>` : ""}
        <div class="score-message-body">${highlightSecurityKeywords(message.body || message.text_preview || "", matchedRules.length ? matchedRules : keywordRules)}</div>
        <div class="mini">${escapeHtml(message.art_id || "")}${message.model ? ` | ${escapeHtml(message.model)}` : ""}</div>
      </article>
    `;
    }).join("")}
  `;
}

function renderKeywordConfigPanel(repositoryId, rules = []) {
  if (!rules.length) return "";
  return `
    <div class="keyword-config-panel">
      <div class="keyword-config-head">
        <div>
          <strong>Keyword scoring</strong>
          <span>Repository ${escapeHtml(repositoryId || "global")}</span>
        </div>
        <span class="mini">Order, color, and weight feed the Review Risk score.</span>
      </div>
      <div class="keyword-config-grid">
        ${rules.map((rule) => `
          <div class="keyword-config-row">
            <span class="keyword-order">${escapeHtml(rule.order)}</span>
            <span class="keyword-color-swatch" style="--keyword-color: ${escapeAttr(rule.color)}"></span>
            <span class="keyword-label">${escapeHtml(rule.label)}</span>
            <span class="keyword-pattern">${escapeHtml(rule.pattern)}</span>
            <span class="keyword-weight">${escapeHtml(rule.weight)}</span>
            <span class="keyword-weight-controls">
              <button class="keyword-adjust" data-keyword-adjust="1" data-repository-id="${escapeAttr(repositoryId || "")}" data-keyword-id="${escapeAttr(rule.id)}" data-delta="-1">-</button>
              <button class="keyword-adjust" data-keyword-adjust="1" data-repository-id="${escapeAttr(repositoryId || "")}" data-keyword-id="${escapeAttr(rule.id)}" data-delta="1">+</button>
            </span>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function keywordChip(rule) {
  return `
    <span class="keyword-chip" style="--keyword-color: ${escapeAttr(rule.color)}">
      <span class="keyword-color-swatch"></span>
      ${escapeHtml(rule.order)}. ${escapeHtml(rule.label)} +${escapeHtml(rule.weight)}
    </span>
  `;
}

async function adjustKeywordWeight(repositoryId, keywordId, delta) {
  if (!keywordId || !delta) return;
  try {
    const value = await api("metadata", "POST", "/keyword-configs:adjust", {
      repository_id: repositoryId || "",
      keyword_id: keywordId,
      delta,
    });
    const updatedRule = (value.rules || []).find((rule) => rule.id === keywordId);
    toast(`${updatedRule?.label || keywordId} weight ${updatedRule?.weight ?? ""}`.trim());
    const context = state.reviewRiskMessageContext;
    if (context) {
      await openReviewRiskMessages(context.changeNumber, context.project, value.repository_id || context.repositoryId || repositoryId || "");
    }
    await refreshReviewRisk({ silent: true });
  } catch (err) {
    toast("Keyword weight update failed", true, err.message);
  }
}

function normalizeKeywordRulesForUi(rules = []) {
  return (Array.isArray(rules) ? rules : [])
    .map((rule) => ({
      id: String(rule.id || ""),
      label: String(rule.label || rule.id || ""),
      pattern: String(rule.pattern || ""),
      color: /^#[0-9a-f]{6}$/i.test(String(rule.color || "")) ? String(rule.color) : "#245da8",
      weight: Number(rule.weight || 0),
      order: Number(rule.order || 0),
      enabled: rule.enabled !== false,
    }))
    .filter((rule) => rule.id && rule.pattern)
    .sort((left, right) => left.order - right.order || left.label.localeCompare(right.label));
}

function highlightSecurityKeywords(text, rules = []) {
  const value = String(text || "");
  const matches = collectKeywordMatches(value, rules);
  let out = "";
  let lastIndex = 0;
  for (const match of matches) {
    const index = match.index;
    out += escapeHtml(value.slice(lastIndex, index));
    out += `<mark class="keyword-mark" style="--keyword-color: ${escapeAttr(match.color)}" title="${escapeAttr(match.label)} +${escapeAttr(match.weight)}">${escapeHtml(value.slice(index, index + match.length))}</mark>`;
    lastIndex = index + match.length;
  }
  out += escapeHtml(value.slice(lastIndex));
  return out;
}

function collectKeywordMatches(value, rules = []) {
  const matches = [];
  for (const rule of normalizeKeywordRulesForUi(rules)) {
    if (!rule.enabled) continue;
    try {
      const regex = new RegExp(rule.pattern, "gi");
      let match;
      while ((match = regex.exec(value)) !== null) {
        const text = match[0] || "";
        if (!text) {
          regex.lastIndex += 1;
          continue;
        }
        matches.push({
          index: match.index || 0,
          length: text.length,
          color: rule.color,
          label: rule.label,
          weight: rule.weight,
        });
      }
    } catch {
      // Bad repository-specific regexes should not break the popup.
    }
  }
  matches.sort((left, right) => left.index - right.index || right.length - left.length);
  const selected = [];
  let lastEnd = -1;
  for (const match of matches) {
    if (match.index < lastEnd) continue;
    selected.push(match);
    lastEnd = match.index + match.length;
  }
  return selected;
}

function closeReviewRiskMessages() {
  const modal = $("#reviewRiskMessageModal");
  if (modal) modal.hidden = true;
}

function clearIdeaCharts() {
  for (const selector of [
    "#ideaReadinessChart",
    "#ideaHeatmapChart",
    "#ideaSignalChart",
    "#changeChurnChart",
    "#changeChurnTable",
    "#signalCaptureChart",
    "#signalCaptureTable",
    "#crossArtifactChart",
    "#crossArtifactTable",
    "#reviewFrictionChart",
    "#reviewFrictionTable",
    "#contradictedApprovalChart",
    "#contradictedApprovalTable",
    "#reviewAbandonmentChart",
    "#reviewAbandonmentTable",
    "#bugThreadHotspotChart",
    "#bugThreadHotspotTable",
    "#componentHotspotChart",
    "#componentHotspotTable",
    "#fileHotspotChart",
    "#fileHotspotTable",
    "#silentSecurityFixChart",
    "#silentSecurityFixTable",
    "#componentConcentrationChart",
    "#componentConcentrationTable",
    "#sensitiveSurfaceChart",
    "#sensitiveSurfaceTable",
    "#sensitiveDisagreementChart",
    "#sensitiveDisagreementTable",
    "#reviewAutomationChart",
    "#reviewAutomationTable",
    "#dependencyHotspotChart",
    "#dependencyHotspotTable",
    "#workflowHotspotChart",
    "#workflowHotspotTable",
    "#ideaTable",
    "#ideaSecuritySignalsTable",
    "#ideaComponentsTable",
    "#ideaLinkEvidenceTable",
  ]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function clearAnalyticsCharts() {
  for (const selector of [
    "#sourceStackedChart",
    "#recordMixChart",
    "#automationChart",
    "#metadataCoverageChart",
    "#relationshipOriginChart",
    "#scenarioReadinessChart",
    "#scenarioReadinessTable",
    "#securitySignalsTable",
    "#topComponentsTable",
    "#topFilesTable",
    "#recentJobsTable",
    "#metadataLinkSamplesTable",
  ]) {
    const node = $(selector);
    if (node) node.innerHTML = "";
  }
}

function drawSourceStackedChart(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  if (!rows.length) return emptyChart(node);
  const keys = ["raw_records", "arts", "metadata", "relationships"];
  const colors = {
    raw_records: "#245da8",
    arts: "#146c63",
    metadata: "#a56315",
    relationships: "#8b4aa9",
  };
  const chartRows = rows.map((row) => ({
    label: `${row.name || row.id} (${row.provider || row.type || "source"})`,
    raw_records: Number(row.raw_records || 0),
    arts: Number(row.arts || 0),
    metadata: Number(row.metadata || 0),
    relationships: Number(row.relationships || 0),
  }));
  const width = Math.max(760, node.clientWidth || 760);
  const height = Math.max(250, 72 + chartRows.length * 58);
  const margin = { top: 34, right: 24, bottom: 48, left: 180 };
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const max = d3lib.max(chartRows, (row) => keys.reduce((total, key) => total + row[key], 0)) || 1;
  const x = d3lib.scaleLinear().domain([0, max]).nice().range([margin.left, width - margin.right]);
  const y = d3lib.scaleBand().domain(chartRows.map((row) => row.label)).range([margin.top, height - margin.bottom]).padding(0.24);
  const stack = d3lib.stack().keys(keys)(chartRows);
  svg.append("g")
    .selectAll("g")
    .data(stack)
    .join("g")
    .attr("fill", (series) => colors[series.key])
    .selectAll("rect")
    .data((series) => series.map((item) => ({ ...item, key: series.key })))
    .join("rect")
    .attr("x", (item) => x(item[0]))
    .attr("y", (item) => y(item.data.label))
    .attr("width", (item) => Math.max(0, x(item[1]) - x(item[0])))
    .attr("height", y.bandwidth())
    .append("title")
    .text((item) => `${item.data.label}\n${item.key}: ${formatNumber(item.data[item.key])}`);
  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(x).ticks(5).tickFormat(d3lib.format("~s")))
    .call((g) => g.select(".domain").remove());
  svg.append("g")
    .attr("transform", `translate(${margin.left},0)`)
    .call(d3lib.axisLeft(y).tickSize(0))
    .call((g) => g.select(".domain").remove())
    .call((g) => g.selectAll("text").attr("font-size", 12));
  drawLegend(svg, keys.map((key) => ({ label: key.replaceAll("_", " "), color: colors[key] })), margin.left, 14);
}

function drawRecordMixChart(selector, data) {
  const rows = [
    ...(data.raw_by_type || []).map((row) => ({ label: `raw: ${row.type}`, count: row.count })),
    ...(data.art_by_type || []).map((row) => ({ label: `art: ${row.type}`, count: row.count })),
  ].slice(0, 12);
  drawHorizontalBarChart(selector, rows, (row) => row.label, (row) => Number(row.count || 0), { color: "#a56315" });
}

function drawHorizontalBarChart(selector, rows, labelFn, valueFn, options = {}) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  if (!rows.length) return emptyChart(node);
  const width = Math.max(640, node.clientWidth || 640);
  const height = Math.max(220, 36 + rows.length * 26);
  const margin = { top: 16, right: 24, bottom: 36, left: 230 };
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const x = d3lib.scaleLinear().domain([0, d3lib.max(rows, valueFn) || 1]).nice().range([margin.left, width - margin.right]);
  const y = d3lib.scaleBand().domain(rows.map(labelFn)).range([margin.top, height - margin.bottom]).padding(0.18);
  svg.append("g")
    .selectAll("rect")
    .data(rows)
    .join("rect")
    .attr("x", margin.left)
    .attr("y", (row) => y(labelFn(row)))
    .attr("width", (row) => x(valueFn(row)) - margin.left)
    .attr("height", y.bandwidth())
    .attr("fill", options.color || "#245da8")
    .append("title")
    .text((row) => `${labelFn(row)}: ${formatNumber(valueFn(row))}`);
  svg.append("g")
    .attr("transform", `translate(${margin.left},0)`)
    .call(d3lib.axisLeft(y).tickSize(0))
    .call((g) => g.select(".domain").remove())
    .call((g) => g.selectAll("text").attr("font-size", 11));
  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(x).ticks(5).tickFormat(d3lib.format("~s")))
    .call((g) => g.select(".domain").remove());
  svg.append("g")
    .selectAll("text.value")
    .data(rows)
    .join("text")
    .attr("class", "value")
    .attr("x", (row) => x(valueFn(row)) + 6)
    .attr("y", (row) => (y(labelFn(row)) || 0) + y.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#667085")
    .text((row) => formatNumber(valueFn(row)));
}

function drawDonutChart(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  const filtered = rows.filter((row) => row.value > 0);
  if (!filtered.length) return emptyChart(node);
  const width = Math.max(320, node.clientWidth || 320);
  const height = 260;
  const radius = Math.min(width, height) / 2 - 24;
  const colors = d3lib.scaleOrdinal().domain(filtered.map((row) => row.label)).range(["#146c63", "#b42318", "#245da8", "#a56315"]);
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const group = svg.append("g").attr("transform", `translate(${width / 2},${height / 2})`);
  const pie = d3lib.pie().value((row) => row.value).sort(null)(filtered);
  const arc = d3lib.arc().innerRadius(radius * 0.58).outerRadius(radius);
  group.selectAll("path")
    .data(pie)
    .join("path")
    .attr("d", arc)
    .attr("fill", (item) => colors(item.data.label))
    .append("title")
    .text((item) => `${item.data.label}: ${formatNumber(item.data.value)}`);
  const total = filtered.reduce((sum, row) => sum + row.value, 0);
  group.append("text").attr("text-anchor", "middle").attr("font-size", 24).attr("font-weight", 700).text(formatNumber(total));
  group.append("text").attr("text-anchor", "middle").attr("y", 19).attr("fill", "#667085").attr("font-size", 12).text("review arts");
  drawLegend(svg, filtered.map((row) => ({ label: `${row.label} ${formatNumber(row.value)}`, color: colors(row.label) })), 14, 18);
}

function drawScenarioChart(selector, rows) {
  const colors = { available: "#087443", partial: "#a56315", missing: "#b42318" };
  drawHorizontalBarChart(
    selector,
    rows,
    (row) => row.idea,
    (row) => ({ available: 3, partial: 2, missing: 1 }[row.status] || 1),
    { color: "#245da8" },
  );
  const node = $(selector);
  const svg = node ? window.d3?.select(node).select("svg") : null;
  if (!svg) return;
  svg.selectAll("rect").attr("fill", (row) => colors[row.status] || "#667085");
}

function drawIdeaReadinessChart(selector, rows) {
  const colors = { available: "#087443", partial: "#a56315", missing: "#b42318" };
  drawHorizontalBarChart(
    selector,
    rows,
    (row) => `${row.number}. ${row.idea}`,
    (row) => row.score,
    { color: "#245da8" },
  );
  const node = $(selector);
  const svg = node ? window.d3?.select(node).select("svg") : null;
  if (!svg) return;
  svg.selectAll("rect").attr("fill", (row) => colors[row.status] || "#667085");
  svg.selectAll("text.value").text((row) => `${row.score}%`);
}

function drawAuthorDefectDensityChart(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  const allData = (rows || [])
    .map((row) => ({
      author: row.author || row.author_id || "unknown",
      commitCount: Number(row.commit_count || 0),
      changedLines: Number(row.changed_lines || 0),
      changedKloc: Number(row.changed_kloc || 0),
      bugLinkedCommits: Number(row.bug_linked_commits || 0),
      securitySignalCommits: Number(row.security_signal_commits || 0),
      commitDensity: Number(row.bug_links_per_1000_commits || 0),
      klocDensity: Number(row.bug_links_per_1000_changed_lines || 0),
    }))
    .filter((row) => row.commitCount > 0);
  const commitData = [...allData]
    .sort((a, b) => b.commitDensity - a.commitDensity || b.commitCount - a.commitCount || a.author.localeCompare(b.author))
    .slice(0, 25);
  const klocData = [...allData]
    .filter((row) => row.changedLines > 0)
    .sort((a, b) => b.klocDensity - a.klocDensity || b.changedLines - a.changedLines || a.author.localeCompare(b.author))
    .slice(0, 25);
  if (!commitData.length && !klocData.length) return emptyChart(node);

  const width = Math.max(1280, node.clientWidth || 1280);
  const height = Math.max(340, 76 + Math.max(commitData.length, klocData.length) * 30);
  const margin = { top: 54, right: 90, bottom: 52, left: 220 };
  const columnGap = 70;
  const rightLabelWidth = 220;
  const barWidth = Math.floor((width - margin.left - rightLabelWidth - columnGap - margin.right) / 2);
  const commitStart = margin.left;
  const commitEnd = commitStart + barWidth;
  const klocLabelStart = commitEnd + columnGap;
  const klocStart = klocLabelStart + rightLabelWidth;
  const klocEnd = width - margin.right;
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const xCommit = d3lib.scaleLinear()
    .domain([0, d3lib.max(commitData, (row) => row.commitDensity) || 1])
    .nice()
    .range([commitStart, commitEnd]);
  const xKloc = d3lib.scaleLinear()
    .domain([0, d3lib.max(klocData, (row) => row.klocDensity) || 1])
    .nice()
    .range([klocStart, klocEnd]);
  const yCommit = d3lib.scaleBand()
    .domain(commitData.map((row) => row.author))
    .range([margin.top, height - margin.bottom])
    .padding(0.18);
  const yKloc = d3lib.scaleBand()
    .domain(klocData.map((row) => row.author))
    .range([margin.top, height - margin.bottom])
    .padding(0.18);

  svg.append("text")
    .attr("x", commitStart)
    .attr("y", 18)
    .attr("font-size", 12)
    .attr("font-weight", 700)
    .attr("fill", "#344054")
    .text("Bug links per 1,000 commits");
  svg.append("text")
    .attr("x", klocLabelStart)
    .attr("y", 18)
    .attr("font-size", 12)
    .attr("font-weight", 700)
    .attr("fill", "#344054")
    .text("Bug links per 1,000 changed LOC");
  svg.append("text")
    .attr("x", klocLabelStart)
    .attr("y", 35)
    .attr("font-size", 11)
    .attr("fill", "#667085")
    .text("Ranked independently");

  svg.append("g")
    .selectAll("rect.commit-density")
    .data(commitData)
    .join("rect")
    .attr("class", "commit-density")
    .attr("x", commitStart)
    .attr("y", (row) => yCommit(row.author))
    .attr("width", (row) => Math.max(1, xCommit(row.commitDensity) - commitStart))
    .attr("height", yCommit.bandwidth())
    .attr("rx", 3)
    .attr("fill", "#b42318")
    .append("title")
    .text((row) => [
      row.author,
      `${formatNumber(row.bugLinkedCommits)} bug-linked commits`,
      `${formatNumber(row.commitCount)} authored commits`,
      `${row.commitDensity} bug links per 1,000 commits`,
      `${formatNumber(row.securitySignalCommits)} security-signal commits`,
    ].join("\n"));

  svg.append("g")
    .selectAll("rect.kloc-density")
    .data(klocData)
    .join("rect")
    .attr("class", "kloc-density")
    .attr("x", klocStart)
    .attr("y", (row) => yKloc(row.author))
    .attr("width", (row) => Math.max(1, xKloc(row.klocDensity) - klocStart))
    .attr("height", yKloc.bandwidth())
    .attr("rx", 3)
    .attr("fill", "#245da8")
    .append("title")
    .text((row) => [
      row.author,
      `${formatNumber(row.bugLinkedCommits)} bug-linked commits`,
      `${formatNumber(row.changedLines)} changed lines`,
      `${row.klocDensity} bug links per 1,000 changed LOC`,
      `${formatNumber(row.securitySignalCommits)} security-signal commits`,
    ].join("\n"));

  svg.append("g")
    .attr("transform", `translate(${commitStart},0)`)
    .call(d3lib.axisLeft(yCommit).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#344054"));

  svg.append("g")
    .attr("transform", `translate(${klocStart},0)`)
    .call(d3lib.axisLeft(yKloc).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#344054"));

  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(xCommit).ticks(4))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));

  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(xKloc).ticks(4))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));

  svg.append("g")
    .selectAll("text.commit-value")
    .data(commitData)
    .join("text")
    .attr("class", "commit-value")
    .attr("x", (row) => xCommit(row.commitDensity) + 6)
    .attr("y", (row) => (yCommit(row.author) || 0) + yCommit.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((row) => `${row.commitDensity}`);

  svg.append("g")
    .selectAll("text.kloc-value")
    .data(klocData)
    .join("text")
    .attr("class", "kloc-value")
    .attr("x", (row) => xKloc(row.klocDensity) + 6)
    .attr("y", (row) => (yKloc(row.author) || 0) + yKloc.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((row) => `${row.klocDensity}`);

  svg.append("text")
    .attr("x", margin.left)
    .attr("y", height - 10)
    .attr("fill", "#667085")
    .attr("font-size", 11)
    .text("KLOC is changed LOC from persisted git commit metadata: insertions + deletions. Minimum 10 commits.");
}

function drawSignalCaptureChart(selector, rows) {
  const colors = { captured: "#087443", partial: "#a56315", weak: "#b42318" };
  drawHorizontalBarChart(
    selector,
    rows,
    (row) => row.signal,
    (row) => row.coverage,
    { color: "#245da8" },
  );
  const node = $(selector);
  const svg = node ? window.d3?.select(node).select("svg") : null;
  if (!svg) return;
  svg.selectAll("rect").attr("fill", (row) => colors[row.status] || "#667085");
  svg.selectAll("text.value").text((row) => `${row.coverage}%`);
}

function drawTopScoreChart(selector, rows, labelFn, scoreKey, color) {
  const sorted = [...(rows || [])]
    .map((row) => ({ ...row, __score: Number(row?.[scoreKey] || 0) }))
    .filter((row) => row.__score > 0)
    .sort((a, b) => b.__score - a.__score)
    .slice(0, 20);
  drawHorizontalBarChart(
    selector,
    sorted,
    (row) => labelFn(row),
    (row) => row.__score,
    { color },
  );
}

function drawReviewRiskStackedChart(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  const chartRows = [...(rows || [])]
    .map((row) => ({
      ...row,
      label: `${row.change_number} ${row.owner || ""}`.trim(),
      risk_score: Number(row.risk_score || 0),
      flat_risk_score: Number(row.flat_risk_score || 0),
    }))
    .filter((row) => row.risk_score > 0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 25);
  if (!chartRows.length) return emptyChart(node);

  const laneColor = (lane) => ({
    urgent_compute: "#b42318",
    high_compute: "#c2410c",
    medium_high_compute: "#a56315",
    security_relevant_routine: "#245da8",
    process_smell_watch: "#7a2e0e",
    process_only_locus: "#667085",
    suppressed_mechanical: "#98a2b3",
  }[lane] || "#0b7285");
  const width = Math.max(900, node.clientWidth || 900);
  const height = Math.max(280, 54 + chartRows.length * 30);
  const margin = { top: 30, right: 96, bottom: 42, left: 180 };
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const x = d3lib.scaleLinear()
    .domain([0, d3lib.max(chartRows, (row) => row.risk_score) || 1])
    .nice()
    .range([margin.left, width - margin.right]);
  const y = d3lib.scaleBand()
    .domain(chartRows.map((row) => row.label))
    .range([margin.top, height - margin.bottom])
    .padding(0.2);

  svg.append("g")
    .selectAll("rect")
    .data(chartRows)
    .join("rect")
    .attr("x", x(0))
    .attr("y", (row) => y(row.label))
    .attr("width", (row) => Math.max(0, x(row.risk_score) - x(0)))
    .attr("height", y.bandwidth())
    .attr("fill", (row) => laneColor(row.priority_lane))
    .append("title")
    .text((row) => [
      `Change ${row.change_number}`,
      row.subject,
      `priority: ${formatNumber(row.risk_score)}`,
      `lane: ${row.priority_lane || ""}`,
      `locus: ${row.security_locus || ""}`,
      `shape: ${row.change_shape || ""}`,
      `legacy flat: ${formatNumber(row.flat_risk_score || 0)}`,
      (row.risk_reasons || []).join(" | "),
    ].filter(Boolean).join("\n"));

  svg.append("g")
    .attr("transform", `translate(${margin.left},0)`)
    .call(d3lib.axisLeft(y).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#344054"));
  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(x).ticks(5))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));
  svg.append("g")
    .selectAll("text.risk-total")
    .data(chartRows)
    .join("text")
    .attr("class", "risk-total")
    .attr("x", (row) => x(row.risk_score) + 6)
    .attr("y", (row) => (y(row.label) || 0) + y.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((row) => `${row.risk_score}`);
  drawLegend(svg, [
    { label: "urgent", color: laneColor("urgent_compute") },
    { label: "high", color: laneColor("high_compute") },
    { label: "medium", color: laneColor("medium_high_compute") },
    { label: "routine", color: laneColor("security_relevant_routine") },
    { label: "process", color: laneColor("process_smell_watch") },
  ], margin.left, 12);
}

function drawReviewerDefectEscapeChart(selector, rows) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  const allData = (rows || [])
    .map((row) => ({
      reviewer: row.reviewer || row.reviewer_author_id || "unknown",
      approvalCount: Number(row.approval_count || 0),
      approvedChangeCount: Number(row.approved_change_count || 0),
      escapedApprovalCount: Number(row.escaped_approval_count || 0),
      escapedChangeCount: Number(row.escaped_change_count || 0),
      approvalDensity: Number(row.escapes_per_1000_approvals || 0),
      changeDensity: Number(row.escapes_per_1000_changes || 0),
    }))
    .filter((row) => row.approvalCount > 0);
  const approvalData = [...allData]
    .sort((a, b) => b.approvalDensity - a.approvalDensity || b.approvalCount - a.approvalCount || a.reviewer.localeCompare(b.reviewer))
    .slice(0, 25);
  const changeData = [...allData]
    .sort((a, b) => b.changeDensity - a.changeDensity || b.approvedChangeCount - a.approvedChangeCount || a.reviewer.localeCompare(b.reviewer))
    .slice(0, 25);
  if (!approvalData.length && !changeData.length) return emptyChart(node);

  const width = Math.max(1280, node.clientWidth || 1280);
  const height = Math.max(340, 76 + Math.max(approvalData.length, changeData.length) * 30);
  const margin = { top: 54, right: 90, bottom: 52, left: 220 };
  const columnGap = 70;
  const rightLabelWidth = 220;
  const barWidth = Math.floor((width - margin.left - rightLabelWidth - columnGap - margin.right) / 2);
  const approvalStart = margin.left;
  const approvalEnd = approvalStart + barWidth;
  const changeLabelStart = approvalEnd + columnGap;
  const changeStart = changeLabelStart + rightLabelWidth;
  const changeEnd = width - margin.right;
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const xApproval = d3lib.scaleLinear()
    .domain([0, d3lib.max(approvalData, (row) => row.approvalDensity) || 1])
    .nice()
    .range([approvalStart, approvalEnd]);
  const xChange = d3lib.scaleLinear()
    .domain([0, d3lib.max(changeData, (row) => row.changeDensity) || 1])
    .nice()
    .range([changeStart, changeEnd]);
  const yApproval = d3lib.scaleBand()
    .domain(approvalData.map((row) => row.reviewer))
    .range([margin.top, height - margin.bottom])
    .padding(0.18);
  const yChange = d3lib.scaleBand()
    .domain(changeData.map((row) => row.reviewer))
    .range([margin.top, height - margin.bottom])
    .padding(0.18);

  svg.append("text").attr("x", approvalStart).attr("y", 18).attr("font-size", 12).attr("font-weight", 700).attr("fill", "#344054").text("Escapes per 1,000 approvals");
  svg.append("text").attr("x", changeLabelStart).attr("y", 18).attr("font-size", 12).attr("font-weight", 700).attr("fill", "#344054").text("Escapes per 1,000 approved changes");
  svg.append("text").attr("x", changeLabelStart).attr("y", 35).attr("font-size", 11).attr("fill", "#667085").text("Ranked independently");

  svg.append("g")
    .selectAll("rect.approval-density")
    .data(approvalData)
    .join("rect")
    .attr("class", "approval-density")
    .attr("x", approvalStart)
    .attr("y", (row) => yApproval(row.reviewer))
    .attr("width", (row) => Math.max(1, xApproval(row.approvalDensity) - approvalStart))
    .attr("height", yApproval.bandwidth())
    .attr("rx", 3)
    .attr("fill", "#8b1e3f")
    .append("title")
    .text((row) => [
      row.reviewer,
      `${formatNumber(row.escapedApprovalCount)} escaped approvals`,
      `${formatNumber(row.approvalCount)} approvals`,
      `${row.approvalDensity} escapes per 1,000 approvals`,
    ].join("\n"));

  svg.append("g")
    .selectAll("rect.change-density")
    .data(changeData)
    .join("rect")
    .attr("class", "change-density")
    .attr("x", changeStart)
    .attr("y", (row) => yChange(row.reviewer))
    .attr("width", (row) => Math.max(1, xChange(row.changeDensity) - changeStart))
    .attr("height", yChange.bandwidth())
    .attr("rx", 3)
    .attr("fill", "#0f766e")
    .append("title")
    .text((row) => [
      row.reviewer,
      `${formatNumber(row.escapedChangeCount)} escaped changes`,
      `${formatNumber(row.approvedChangeCount)} approved changes`,
      `${row.changeDensity} escapes per 1,000 approved changes`,
    ].join("\n"));

  svg.append("g")
    .attr("transform", `translate(${approvalStart},0)`)
    .call(d3lib.axisLeft(yApproval).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#344054"));
  svg.append("g")
    .attr("transform", `translate(${changeStart},0)`)
    .call(d3lib.axisLeft(yChange).tickSize(0))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#344054"));
  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(xApproval).ticks(4))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));
  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3lib.axisBottom(xChange).ticks(4))
    .call((group) => group.select(".domain").remove())
    .call((group) => group.selectAll("text").attr("font-size", 11).attr("fill", "#667085"));
  svg.append("g")
    .selectAll("text.approval-value")
    .data(approvalData)
    .join("text")
    .attr("class", "approval-value")
    .attr("x", (row) => xApproval(row.approvalDensity) + 6)
    .attr("y", (row) => (yApproval(row.reviewer) || 0) + yApproval.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((row) => `${row.approvalDensity}`);
  svg.append("g")
    .selectAll("text.change-value")
    .data(changeData)
    .join("text")
    .attr("class", "change-value")
    .attr("x", (row) => xChange(row.changeDensity) + 6)
    .attr("y", (row) => (yChange(row.reviewer) || 0) + yChange.bandwidth() / 2 + 4)
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((row) => `${row.changeDensity}`);
  svg.append("text")
    .attr("x", approvalStart)
    .attr("y", height - 10)
    .attr("fill", "#667085")
    .attr("font-size", 11)
    .text("Based on any positive approval linked to Gerrit changes that later map to bug-linked commits.");
}

function drawIdeaHeatmapChart(selector, ideas, signals) {
  const node = $(selector);
  const d3lib = window.d3;
  if (!node || !d3lib) return;
  node.innerHTML = "";
  if (!ideas.length || !signals.length) return emptyChart(node);
  const activeSignals = signals.filter((signal) => signal.count > 0 || ["repo_settings", "release_boundaries"].includes(signal.id));
  const width = Math.max(1120, node.clientWidth || 1120);
  const height = Math.max(520, 86 + ideas.length * 24);
  const margin = { top: 118, right: 24, bottom: 24, left: 270 };
  const svg = d3lib.select(node).append("svg").attr("viewBox", [0, 0, width, height]);
  const x = d3lib.scaleBand().domain(activeSignals.map((signal) => signal.id)).range([margin.left, width - margin.right]).padding(0.08);
  const y = d3lib.scaleBand().domain(ideas.map((idea) => idea.number)).range([margin.top, height - margin.bottom]).padding(0.1);
  const max = d3lib.max(activeSignals, (signal) => signal.count) || 1;
  const color = d3lib.scaleSequentialLog([1, max + 1], d3lib.interpolateYlGnBu);
  const cells = [];
  for (const idea of ideas) {
    for (const signal of activeSignals) {
      const count = idea.signalCounts[signal.id] || 0;
      cells.push({ idea, signal, count });
    }
  }
  svg.append("g")
    .selectAll("rect")
    .data(cells)
    .join("rect")
    .attr("x", (cell) => x(cell.signal.id))
    .attr("y", (cell) => y(cell.idea.number))
    .attr("width", x.bandwidth())
    .attr("height", y.bandwidth())
    .attr("rx", 2)
    .attr("fill", (cell) => cell.count > 0 ? color(cell.count + 1) : "#eef2f6")
    .attr("stroke", "#ffffff")
    .append("title")
    .text((cell) => `${cell.idea.number}. ${cell.idea.idea}\n${cell.signal.label}: ${formatNumber(cell.count)}`);
  svg.append("g")
    .selectAll("text.idea-label")
    .data(ideas)
    .join("text")
    .attr("class", "idea-label")
    .attr("x", margin.left - 10)
    .attr("y", (idea) => (y(idea.number) || 0) + y.bandwidth() / 2 + 4)
    .attr("text-anchor", "end")
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((idea) => `${idea.number}. ${idea.idea}`);
  svg.append("g")
    .selectAll("text.signal-label")
    .data(activeSignals)
    .join("text")
    .attr("class", "signal-label")
    .attr("transform", (signal) => `translate(${(x(signal.id) || 0) + x.bandwidth() / 2},${margin.top - 10}) rotate(-50)`)
    .attr("text-anchor", "start")
    .attr("font-size", 11)
    .attr("fill", "#344054")
    .text((signal) => signal.label);
}

function drawLegend(svg, rows, x, y) {
  const group = svg.append("g").attr("transform", `translate(${x},${y})`);
  let offset = 0;
  for (const row of rows) {
    const item = group.append("g").attr("transform", `translate(${offset},0)`);
    item.append("rect").attr("width", 10).attr("height", 10).attr("rx", 2).attr("fill", row.color);
    item.append("text").attr("x", 15).attr("y", 10).attr("font-size", 11).attr("fill", "#667085").text(row.label);
    offset += Math.min(190, 28 + row.label.length * 7);
  }
}

function emptyChart(node) {
  node.innerHTML = `<p class="mini">No data.</p>`;
}

function renderAnalyticsTable(selector, headings, rows, rowFn) {
  const node = $(selector);
  if (!node) return;
  node.innerHTML = `
    <table>
      <thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join("")}</tr></thead>
      <tbody>
        ${rows.map((row) => `<tr>${rowFn(row).map((cell) => `<td>${escapeHtml(formatCell(cell))}</td>`).join("")}</tr>`).join("")}
      </tbody>
    </table>
  `;
}

function buildScenarioReadiness(data) {
  return buildIdeaReadiness(data);
}

function buildSignalCaptureMatrix(data) {
  const definitions = [
    ["Review friction", [
      ["Patch sets", metadataCount(data, "code_review", "patch_set")],
      ["Comment totals", metadataCount(data, "code_review.gerrit", "total_comment_count")],
      ["Unresolved comments", metadataCount(data, "code_review.gerrit", "unresolved_comment_count")],
      ["Review messages", metadataCount(data, "review.gerrit", "message_event")],
    ]],
    ["Contradicted approvals", [
      ["Approval votes", metadataCount(data, "review.approval", "vote")],
      ["Approval-change links", linkCount(data, "normalizer.metadata_link.approval_change")],
      ["Reviewer links", linkCount(data, "normalizer.metadata_author_link.v1")],
    ]],
    ["Silent security-fix candidates", [
      ["Security signals", metadataCount(data, "security.signal", null)],
      ["Commit SHAs", metadataCount(data, "git.commit", "sha")],
      ["Security identifiers", metadataCount(data, "security.identifier", null)],
    ]],
    ["Review abandonment", [
      ["Change status", metadataCount(data, "code_review.gerrit", "status")],
      ["Patch sets", metadataCount(data, "code_review", "patch_set")],
    ]],
    ["Rework / instability", [
      ["Patch sets", metadataCount(data, "code_review", "patch_set")],
      ["Approval votes", metadataCount(data, "review.approval", "vote")],
      ["Review messages", metadataCount(data, "review.gerrit", "message_event")],
      ["Unresolved comments", metadataCount(data, "code_review.gerrit", "unresolved_comment_count")],
    ]],
    ["Change churn shape", [
      ["Commit insertions", metadataCount(data, "git.commit", "insertions")],
      ["Commit deletions", metadataCount(data, "git.commit", "deletions")],
      ["Changed file counts", metadataCount(data, "git.commit", "changed_file_count")],
      ["Binary file counts", metadataCount(data, "git.commit", "binary_file_count")],
      ["Review insertions", metadataCount(data, "code_review.gerrit", "insertions")],
      ["Review deletions", metadataCount(data, "code_review.gerrit", "deletions")],
    ]],
    ["Component concentration", [
      ["Components", metadataCount(data, "code.component", "name")],
      ["Authored-by links", relationCount(data, "authored_by")],
      ["Change-component links", linkCount(data, "normalizer.metadata_link.gerrit_change_component")],
    ]],
    ["File hotspots", [
      ["File paths", metadataCount(data, "code.file", "path")],
      ["Change-file links", linkCount(data, "normalizer.metadata_link.gerrit_change_file")],
      ["Security signals", metadataCount(data, "security.signal", null)],
    ]],
    ["Bug-thread exposure", [
      ["Bug ids", metadataCount(data, "issue.launchpad", "bug_id")],
      ["Duplicate counts", metadataCount(data, "issue.launchpad", "duplicate_count")],
      ["Message counts", metadataCount(data, "issue.launchpad", "message_count")],
      ["Security-related", metadataCount(data, "issue.launchpad", "security_related")],
      ["Private bugs", metadataCount(data, "issue.launchpad", "private")],
      ["Bug heat", metadataCount(data, "issue.launchpad", "heat")],
    ]],
    ["Dependency-change exposure", [
      ["Dependency paths", signalCount(data, "dependency_paths")],
      ["Dependency risk scenarios", metadataCount(data, "security.scenario", "dependency_update_risk")],
      ["Dependency file roles", metadataCount(data, "code.file_role", "role")],
    ]],
    ["Workflow / CI risk exposure", [
      ["Workflow paths", signalCount(data, "workflow_paths")],
      ["Workflow risk scenarios", metadataCount(data, "security.scenario", "cicd_workflow_risk")],
      ["Automated review messages", metadataCount(data, "code_review", "automated")],
    ]],
    ["Sensitive-surface hotspots", [
      ["Security signals", metadataCount(data, "security.signal", null)],
      ["Components", metadataCount(data, "code.component", "name")],
      ["File roles", metadataCount(data, "code.file_role", "role")],
    ]],
    ["Sensitive review disagreement", [
      ["Approval votes", metadataCount(data, "review.approval", "vote")],
      ["Security signals", metadataCount(data, "security.signal", null)],
      ["Unresolved comments", metadataCount(data, "code_review.gerrit", "unresolved_comment_count")],
    ]],
    ["Human vs automated review ratio", [
      ["Review automation flags", metadataCount(data, "code_review", "automated")],
      ["Review message kinds", metadataCount(data, "code_review", "message_kind")],
      ["Code review arts", typeCount(data, "code_review_message")],
    ]],
    ["Cross-artifact convergence", [
      ["Commit-bug links", linkCount(data, "normalizer.metadata_link.commit_bug")],
      ["Change-file links", linkCount(data, "normalizer.metadata_link.gerrit_change_file")],
      ["Change-component links", linkCount(data, "normalizer.metadata_link.gerrit_change_component")],
      ["Security signals", metadataCount(data, "security.signal", null)],
    ]],
  ];
  return definitions.map(([signal, evidence]) => {
    const present = evidence.filter((item) => item[1] > 0).map(([label, count]) => `${label} ${formatNumber(count)}`);
    const missing = evidence.filter((item) => item[1] <= 0).map(([label]) => label);
    const coverage = Math.round((present.length / Math.max(1, evidence.length)) * 100);
    const status = coverage === 100 ? "captured" : coverage >= 50 ? "partial" : "weak";
    return { signal, present, missing, coverage, status };
  });
}

function buildIdeaReadiness(data) {
  const definitions = [
    [1, "Author defect density", ["authors", "commit_bug_links", "bug_nodes"], ["confirmed defect/vulnerability outcomes"]],
    [2, "Reviewer defect-escape density", ["review_votes", "review_author_links", "change_component_links"], ["merge outcome to later defect links"]],
    [3, "Component reviewer-fit score", ["review_votes", "review_author_links", "change_component_links", "change_file_links"], ["reviewer history by component"]],
    [4, "Security-sensitive change detector", ["security_signals", "file_paths", "components", "churn"], ["semantic diff facts"]],
    [5, "Attack-surface delta analysis", ["file_paths", "churn", "security_signals"], ["parsed routes/APIs/RPC/webhooks"]],
    [6, "Silent security-fix detector", ["security_signals", "churn", "commit_bug_links"], ["validation/bounds/sanitization diff facts"]],
    [7, "Vulnerability precursor mining", ["bug_lifecycle", "review_votes", "security_signals", "bug_nodes"], ["cross-record temporal model"]],
    [8, "Bug-to-vulnerability conversion model", ["bug_nodes", "bug_lifecycle", "security_signals"], ["later vulnerability labels"]],
    [9, "Duplicate bug cluster vulnerability detection", ["bug_nodes", "bug_lifecycle"], ["duplicate-of links and text clustering"]],
    [10, "Security concern ignored detector", ["review_votes", "review_author_links", "security_signals", "change_file_links"], ["dismiss/defer resolution states"]],
    [11, "Component vulnerability pressure index", ["components", "churn", "security_signals", "commit_bug_links", "review_votes"], ["historical vulnerability outcomes"]],
    [12, "Security knowledge decay index", ["authors", "review_author_links", "components", "change_component_links"], ["maintainer/reviewer tenure over time"]],
    [13, "Security-critical file lineage", ["file_paths", "security_signals", "commit_bug_links", "change_file_links"], ["longitudinal file risk rollups"]],
    [14, "Vulnerability-introducing commit reconstruction", ["commit_shas", "commit_bug_links", "change_commit_links"], ["introducing-commit tracing"]],
    [15, "Fix propagation and backport gap analysis", ["branches", "change_commit_links", "commit_shas"], ["branch/release backport graph"]],
    [16, "Security-fix quality and regression detector", ["commit_bug_links", "bug_lifecycle", "commit_shas"], ["revert/reopen/follow-up classification"]],
    [17, "Release vulnerability readiness score", ["security_signals", "churn", "review_votes", "branches"], ["release candidate boundaries"]],
    [18, "CI/CD workflow risk graph", ["ci_messages", "workflow_paths"], ["parsed workflow/job/permission entities"]],
    [19, "Repository-control drift detection", ["repo_settings"], ["branch protection/settings/CODEOWNERS history"]],
    [20, "Dependency update risk score", ["dependency_paths", "file_paths", "review_votes"], ["package/version dependency graph"]],
  ];
  return definitions.map(([number, idea, signalIds, missingInputs]) => {
    const metrics = signalIds.map((id) => ({
      id,
      label: ideaSignalLabels[id] || id,
      count: signalCount(data, id),
    }));
    const present = metrics.filter((metric) => metric.count > 0).map((metric) => `${metric.label} (${formatNumber(metric.count)})`);
    const missingSignals = metrics.filter((metric) => metric.count === 0).map((metric) => metric.label);
    const missing = [...missingSignals, ...missingInputs];
    const score = Math.round((present.length / Math.max(1, metrics.length + missingInputs.length)) * 100);
    const status = score >= 75 ? "available" : score > 0 ? "partial" : "missing";
    const signalCounts = {};
    for (const metric of metrics) signalCounts[metric.id] = metric.count;
    return { number, idea, status, score, present, missing, metrics, signalCounts };
  });
}

function metadataCount(data, namespace, key) {
  return (data.metadata_by_namespace_key || [])
    .filter((row) => row.namespace === namespace && (key === null || row.key === key))
    .reduce((sum, row) => sum + Number(row.count || 0), 0);
}

function linkCount(data, origin) {
  return Number((data.relationship_by_origin || []).find((row) => row.origin === origin)?.count || 0);
}

function relationCount(data, relation) {
  return (data.relationship_by_relation || [])
    .filter((row) => row.relation === relation)
    .reduce((sum, row) => sum + Number(row.count || 0), 0);
}

function typeCount(data, type) {
  return Number((data.art_by_type || []).find((row) => row.type === type)?.count || 0);
}

function ideaSignalRows(data) {
  return Object.entries(ideaSignalLabels).map(([id, label]) => ({
    id,
    label,
    count: signalCount(data, id),
  }));
}

function signalCount(data, id) {
  return Number((data.idea_signal_counts || []).find((row) => row.signal === id)?.count || 0);
}

function renderList(selector, records = [], title) {
  $(selector).innerHTML = records.map((record) => {
    const [head, body] = title(record);
    return recordCard(record, { title: head, subtitle: body });
  }).join("") || `<p class="mini">No records.</p>`;
}

async function retrievalSweep() {
  const calls = [
    ["Repointel health", "repointel", "GET", "/healthz"],
    ["Metadata health", "metadata", "GET", "/healthz"],
    ...repointelCollections.map((collection) => [`Repointel ${collection}`, "repointel", "GET", `/${collection}`]),
    ...metadataCollections.map((collection) => [`Metadata ${collection}`, "metadata", "GET", `/${collection}`]),
  ];
  const selected = state.selected;
  if (selected.kind === "repo") {
    calls.push(["Selected repository", "repointel", "GET", `/repositories/${selected.id}`]);
    calls.push(["Selected repository sources", "repointel", "GET", `/repositories/${selected.id}/sources`]);
  }
  if (selected.kind === "source") {
    for (const suffix of ["", "/ingestion-jobs", "/raw-records", "/arts", "/metadata", "/relationships"]) {
      calls.push([`Selected source${suffix}`, "repointel", "GET", `/sources/${selected.id}${suffix}`]);
    }
  }
  if (state.selected.collectionRunId) {
    calls.push(["Selected collection run", "metadata", "GET", `/runs/${state.selected.collectionRunId}`]);
    calls.push(["Selected run evidence", "metadata", "GET", `/runs/${state.selected.collectionRunId}/evidence-hits`]);
    calls.push(["Selected run traces", "metadata", "GET", `/runs/${state.selected.collectionRunId}/downstream-calls`]);
  }
  const rows = [];
  for (const [label, service, method, path] of calls) {
    const result = await safeApi(service, method, path);
    rows.push({ label, service, method, path, ...result });
    $("#sweepResults").innerHTML = rows.map(sweepRow).join("");
  }
  toast("Retrieval sweep complete");
}

function sweepRow(row) {
  const countValue = row.value ? countItems(row.value) : 0;
  return `
    <div class="sweep-row">
      <div class="record-title">
        <span>${escapeHtml(row.label)}</span>
        <span class="${row.ok ? "status-ok" : "status-bad"}">${row.ok ? "OK" : "ERR"}</span>
      </div>
      <div class="record-body">${escapeHtml(row.method)} ${escapeHtml(row.path)} ${row.ms ? `${Math.round(row.ms)}ms` : ""} ${countValue ? `items=${countValue}` : ""}</div>
      ${row.error ? `<div class="mini">${escapeHtml(row.error)}</div>` : ""}
    </div>
  `;
}

async function submitGroup(event) {
  event.preventDefault();
  const body = compact(formValue(event.currentTarget));
  const groupId = body.group_id;
  delete body.group_id;
  const result = groupId
    ? await api("repointel", "PATCH", `/repository-groups/${encodeURIComponent(groupId)}`, body)
    : await api("repointel", "POST", "/repository-groups", body);
  state.selected = { kind: "group", id: result.id, item: result };
  await refreshTopology();
  toast(groupId ? "Repository group updated" : "Repository group created");
}

async function submitRepo(event) {
  event.preventDefault();
  const body = compact(formValue(event.currentTarget));
  const repositoryId = body.repository_id;
  delete body.repository_id;
  const result = repositoryId
    ? await api("repointel", "PATCH", `/repositories/${encodeURIComponent(repositoryId)}`, body)
    : await api("repointel", "POST", "/repositories", body);
  state.selected = { kind: "repo", id: result.id, item: result, repositoryMode: "" };
  state.repositoryDetailTab = "repository";
  await refreshTopology();
  toast(repositoryId ? "Repository updated" : "Repository created");
}

async function submitSource(event) {
  event.preventDefault();
  const form = formValue(event.currentTarget);
  const sourceId = form.source_id?.trim();
  const body = sourceFormBody(form);
  const result = sourceId
    ? await api("repointel", "PATCH", `/sources/${encodeURIComponent(sourceId)}`, body)
    : await api("repointel", "POST", "/sources", body);
  state.selected = { kind: "source", id: result.id, item: result };
  await refreshTopology();
  toast(sourceId ? "Source updated" : "Source created");
}

async function submitJob(event) {
  event.preventDefault();
  const body = compact(formValue(event.currentTarget));
  const jobId = body.job_id;
  delete body.job_id;
  if (body.priority !== undefined) body.priority = Number(body.priority);
  const result = jobId
    ? await api("repointel", "PATCH", `/ingestion-jobs/${encodeURIComponent(jobId)}`, body)
    : await api("repointel", "POST", "/ingestion-jobs", body);
  selectJob(result.id);
  await refreshIngestion();
  toast(jobId ? "Ingestion job updated" : "Ingestion job created");
}

async function deleteSelectedResource(kind) {
  const id = resourceFormId(kind);
  if (!id) return toast(`Select or enter a ${kind} first`, true);
  const parentRepo = kind === "source" ? selectedRepository() : null;
  const labels = {
    group: "repository group",
    repo: "repository",
    source: "source",
  };
  if (!window.confirm(`Delete ${labels[kind]} ${id}?`)) return;
  const path = {
    group: `/repository-groups/${encodeURIComponent(id)}`,
    repo: `/repositories/${encodeURIComponent(id)}`,
    source: `/sources/${encodeURIComponent(id)}`,
  }[kind];
  await api("repointel", "DELETE", path);
  if (kind === "source" && parentRepo) {
    state.selected = { kind: "repo", id: parentRepo.id, item: parentRepo, repositoryMode: "" };
    state.repositoryDetailTab = "sources";
  } else if (state.selected.kind === kind && state.selected.id === id) {
    state.selected = {};
  }
  await refreshTopology();
  toast(`${labels[kind]} deleted`);
}

function resourceFormId(kind) {
  if (kind === "group") return $("#groupForm [name='group_id']")?.value.trim() || (state.selected.kind === "group" ? state.selected.id : "");
  if (kind === "repo") return $("#repoForm [name='repository_id']")?.value.trim() || (state.selected.kind === "repo" ? state.selected.id : "");
  if (kind === "source") return $("#sourceForm [name='source_id']")?.value.trim() || (state.selected.kind === "source" ? state.selected.id : "");
  return "";
}

async function deleteSelectedJob() {
  const jobId = $("#createJobForm [name='job_id']")?.value.trim() || state.selected.jobId;
  if (!jobId) return toast("Select or enter an ingestion job first", true);
  if (!window.confirm(`Delete ingestion job ${jobId}?`)) return;
  await api("repointel", "DELETE", `/ingestion-jobs/${encodeURIComponent(jobId)}`);
  if (state.selected.jobId === jobId) {
    state.selected.jobId = "";
    state.selected.jobMembers = null;
  }
  await refreshIngestion();
  resetJobForm();
  toast("Ingestion job deleted");
}

async function submitNormalizer(event) {
  event.preventDefault();
  const result = await api("repointel", "POST", "/normalizers", compact(formValue(event.currentTarget)));
  state.selected.normalizerId = result.id;
  $("#normalizerTestForm [name='normalizer_id']").value = result.id;
  await refreshNormalizers();
  toast("Normalizer created");
}

async function submitNormalizerTest(event) {
  event.preventDefault();
  const body = compact(formValue(event.currentTarget));
  body.params = parseJson(body.params, {});
  const id = body.normalizer_id;
  delete body.normalizer_id;
  const result = await api("repointel", "POST", `/normalizers/${id}/test`, body);
  $("#normalizerResult").textContent = pretty(result);
  toast("Normalizer test completed");
}

async function seedProfile() {
  const result = await api("metadata", "POST", "/profiles:seed-vuln-intel-priority-v1", {});
  await refreshCollection();
  toast(`Seeded ${result.slug}`);
}

async function ensureProfileSeeded() {
  if ((state.data.profiles || []).some((profile) => profile.id === "profile_vuln_intel_priority_v1")) return;
  await api("metadata", "POST", "/profiles:seed-vuln-intel-priority-v1", { force: false });
  await refreshCollection();
}

async function planCollection() {
  await ensureProfileSeeded();
  const body = collectionRunBody();
  const result = await api("metadata", "POST", "/runs:plan", body);
  $("#collectionPlan").textContent = pretty(result);
  toast("Collection plan returned");
}

async function submitCollectionRun(event) {
  event.preventDefault();
  await ensureProfileSeeded();
  const result = await api("metadata", "POST", "/runs", collectionRunBody());
  state.selected.collectionRunId = result.id;
  await refreshCollection();
  toast("Collection run completed");
}

async function commitAccepted() {
  const runId = state.selected.collectionRunId;
  if (!runId) return toast("Select a collection run first", true);
  const result = await api("metadata", "POST", "/evidence-hits:commit", {
    collection_run_id: runId,
    disposition_filter: "accepted",
    min_confidence: 0,
    dry_run: false,
    write_extraction_evidence_metadata: true,
    params: {},
  });
  $("#collectionPlan").textContent = pretty(result);
  await refreshCollection();
  await refreshEvidence();
  toast("Accepted evidence committed");
}

async function browserFetch() {
  const form = formValue($("#browserForm"));
  const service = form.service;
  const collection = form.collection;
  const id = form.id?.trim();
  let result;
  if (id) {
    result = await api(service, "GET", `/${collection}/${encodeURIComponent(id)}`);
  } else if (form.query || form.filters) {
    const searchPath = service === "metadata" && collection === "szz-runs" ? "/szz-analyses:search" : `/${collection}:search`;
    result = await api(service, "POST", searchPath, {
      query: form.query || "",
      filters: parseJson(form.filters, {}),
      limit: Number(form.limit || 100),
    });
  } else {
    result = await api(service, "GET", `/${collection}`);
  }
  $("#browserResult").textContent = pretty(result);
}

function sourceFormBody(form) {
  const policy = {};
  const limit = Number(form.limit || 0);
  const reviewsPerMinute = Number(form.reviews_per_minute || 0);
  const commentsPerChange = Number(form.comments_per_change || 0);
  if (limit > 0) {
    policy.limit = limit;
    if (form.provider === "gerrit") policy.review_limit = limit;
  }
  if (form.provider === "git" && form.local_path) policy.local_path = form.local_path;
  if (reviewsPerMinute > 0) policy.reviews_per_minute = reviewsPerMinute;
  if (form.provider === "gerrit" && commentsPerChange > 0) policy.comments_per_change = commentsPerChange;
  policy.include_automated_messages = Boolean(form.include_automated_messages);
  const body = compact({
    repository_id: form.repository_id,
    name: form.name,
    type: form.type,
    provider: form.provider,
    base_url: form.base_url,
    external_key: form.external_key,
    enabled: Boolean(form.enabled),
    ingestion_policy: policy,
    ingestion_filters: {},
  });
  return body;
}

function collectionRunBody() {
  const form = formValue($("#collectionRunForm"));
  const selector = compact({
    repository_id: form.repository_id,
    source_ids: csv(form.source_ids),
    art_types: csv(form.art_types),
    limit: 1000,
  });
  return compact({
    profile_id: form.profile_id || "profile_vuln_intel_priority_v1",
    selector,
    requested_by: "debug-console",
    mode: form.mode || "incremental",
    dry_run: false,
    auto_commit: Boolean(form.auto_commit),
    min_confidence: Number(form.min_confidence || 0.85),
    review_below_confidence: Number(form.review_below_confidence || 0.85),
    priority: 10,
    params: {},
  });
}

function selectionCollectionBody(sources, dryRun) {
  return compact({
    profile_id: $("#collectionRunForm [name='profile_id']").value || "profile_vuln_intel_priority_v1",
    selector: {
      repository_group_id: state.selected.kind === "group" ? state.selected.id : "",
      repository_id: selectedRepositoryIdForSources(sources),
      source_ids: sources.map((source) => source.id),
      art_types: csv($("#collectionRunForm [name='art_types']").value),
      limit: 1000,
    },
    scenario_ids: [],
    bundle_ids: [],
    rule_ids: [],
    requested_by: "debug-console",
    mode: $("#collectionRunForm [name='mode']").value || "incremental",
    dry_run: Boolean(dryRun),
    auto_commit: Boolean($("#collectionRunForm [name='auto_commit']").checked),
    min_confidence: Number($("#collectionRunForm [name='min_confidence']").value || 0.85),
    review_below_confidence: Number($("#collectionRunForm [name='review_below_confidence']").value || 0.85),
    priority: 10,
    params: {},
  });
}

function renderBrowserCollections() {
  const form = $("#browserForm");
  const collectionSelect = $("#browserCollection");
  if (!form || !collectionSelect) return;
  const service = form.elements.service.value;
  const collections = service === "metadata" ? metadataCollections : repointelCollections;
  collectionSelect.innerHTML = collections.map((collection) => `<option>${collection}</option>`).join("");
}

async function list(service, path) {
  return items(await api(service, "GET", path));
}

async function searchList(service, path, filters = {}, limit = 500) {
  return items(await api(service, "POST", path, {
    query: "",
    filters,
    limit,
  }));
}

async function api(service, method, path, body) {
  const base = service === "metadata" ? state.config.metadataProxy : state.config.repointelProxy;
  const token = service === "metadata" ? state.config.metadataToken : state.config.repointelToken;
  const started = performance.now();
  const entry = { service, method, path, body, started: new Date().toISOString() };
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  try {
    const response = await fetch(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    const value = text ? parseJson(text, text) : null;
    Object.assign(entry, {
      status: response.status,
      ms: performance.now() - started,
      response: value,
      ok: response.ok,
    });
    state.calls.unshift(entry);
    entry.logged = true;
    renderCalls();
    showRestToast(entry);
    if (!response.ok) {
      throw new Error(value?.message || value?.error || `${method} ${path} failed with ${response.status}`);
    }
    return value;
  } catch (err) {
    if (!entry.logged) {
      Object.assign(entry, { status: "ERR", ms: performance.now() - started, response: { error: err.message }, ok: false });
      state.calls.unshift(entry);
      renderCalls();
      showRestToast(entry);
    }
    throw err;
  }
}

function showRestToast(call) {
  const status = String(call.status);
  const ms = Math.round(call.ms || 0);
  toast(`${call.method} ${call.path} -> ${status}`, !call.ok, `${ms}ms ${responseSummary(call.response)}`);
}

function responseSummary(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string") return value.slice(0, 700);
  const parts = [];
  if (value._frontplane?.operation) parts.push(value._frontplane.operation);
  if (value.id) parts.push(`id=${value.id}`);
  if (value.status) parts.push(`status=${value.status}`);
  if (value.message) parts.push(value.message);
  if (value.error) parts.push(`${value.error}${value.message ? "" : ""}`);
  if (Array.isArray(value.items)) parts.push(`items=${value.items.length}`);
  if (value.page?.total !== undefined) parts.push(`total=${value.page.total}`);
  for (const key of [
    "raw_records_count",
    "arts_count",
    "authors_count",
    "metadata_count",
    "relationships_count",
    "evidence_hits_count",
    "metadata_upserted_count",
    "relationships_upserted_count",
    "downstream_calls_count",
  ]) {
    if (value[key] !== undefined) parts.push(`${key}=${value[key]}`);
  }
  const summary = parts.filter(Boolean).join(" | ");
  return summary || pretty(value).slice(0, 700);
}

async function safeApi(service, method, path, body) {
  const started = performance.now();
  try {
    const value = await api(service, method, path, body);
    return { ok: true, value, ms: performance.now() - started };
  } catch (err) {
    return { ok: false, error: err.message, ms: performance.now() - started };
  }
}

function renderCalls() {
  const node = $("#callLog");
  if (!node) return;
  node.innerHTML = state.calls.slice(0, 200).map((call, index) => `
    <div class="call-row">
      <div class="${call.ok ? "status-ok" : "status-bad"}">${escapeHtml(String(call.status))}</div>
      <div>
        <strong>${escapeHtml(call.service)} ${escapeHtml(call.method)} ${escapeHtml(call.path)}</strong>
        <div class="mini">${escapeHtml(call.started)} ${Math.round(call.ms || 0)}ms</div>
      </div>
      <button data-call="${index}" data-side="body">Request</button>
      <button data-call="${index}" data-side="response">Response</button>
    </div>
  `).join("") || `<p class="mini">No API calls yet.</p>`;
  $$("#callLog button").forEach((button) => {
    button.addEventListener("click", () => {
      const call = state.calls[Number(button.dataset.call)];
      const payload = button.dataset.side === "body" ? call.body : call.response;
      const browserResult = $("#browserResult");
      if (browserResult) browserResult.textContent = pretty(payload);
      const browserButton = $$(".nav button").find((item) => item.dataset.tab === "browser");
      if (browserButton) browserButton.click();
    });
  });
}

function formValue(form) {
  const out = {};
  for (const field of new FormData(form).entries()) out[field[0]] = field[1];
  $$("input[type='checkbox']", form).forEach((checkbox) => {
    out[checkbox.name] = checkbox.checked;
  });
  return out;
}

function compact(value) {
  if (Array.isArray(value)) return value.map(compact).filter((item) => !isEmpty(item));
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    const next = compact(item);
    if (!isEmpty(next)) out[key] = next;
  }
  return out;
}

function isEmpty(value) {
  return value === "" || value === null || value === undefined || (Array.isArray(value) && value.length === 0);
}

function csv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function items(value) {
  return value?.items || value?.response?.items || [];
}

function countItems(value) {
  return items(value).length || (Array.isArray(value) ? value.length : value && typeof value === "object" ? 1 : 0);
}

function count(key) {
  const loaded = (state.data[key] || []).length;
  const collection = {
    groups: "repository-groups",
    repositories: "repositories",
    sources: "sources",
    ingestionJobs: "ingestion-jobs",
    ingestionLogs: "ingestion-logs",
    rawRecords: "raw-records",
    arts: "arts",
    authors: "authors",
    metadata: "metadata",
    relationships: "relationships",
    normalizers: "normalizers",
  }[key];
  if (!loaded && collection) {
    return Number((state.data.analytics?.collection_counts || []).find((row) => row.collection === collection)?.count || 0);
  }
  return loaded;
}

function statCard(label, value) {
  return `<div class="stat-card"><div class="value">${value}</div><div class="label">${escapeHtml(label)}</div></div>`;
}

function recordCard(record, options = {}) {
  const title = options.title || record.name || record.slug || record.id || "record";
  const subtitle = options.subtitle || record.id || "";
  return `
    <div class="record ${options.selected ? "selected" : ""}" ${options.attrs || ""}>
      <div class="record-title">
        <span>${escapeHtml(String(title))}</span>
        ${record.status ? `<span class="chip">${escapeHtml(record.status)}</span>` : ""}
      </div>
      <div class="record-body">${escapeHtml(String(subtitle))}</div>
    </div>
  `;
}

function resultCard(label, result) {
  return `
    <div class="record">
      <div class="record-title">
        <span>${escapeHtml(label)}</span>
        <span class="${result.ok ? "status-ok" : "status-bad"}">${result.ok ? "OK" : "ERR"}</span>
      </div>
      <div class="record-body">${result.ok ? `${countItems(result.value)} item(s)` : escapeHtml(result.error || "")}</div>
      <pre class="json-card">${escapeHtml(pretty(result.value || result.error))}</pre>
    </div>
  `;
}

function summaryTable(item) {
  return `<div class="json-card">${escapeHtml(pretty(item))}</div>`;
}

function selectionSummary(kind, item) {
  if (!item.id) return summaryTable(item);
  const stats = [];
  if (kind === "group") {
    const repos = (state.data.repositories || []).filter((repo) => repo.repository_group_id === item.id);
    const sources = (state.data.sources || []).filter((source) => repos.some((repo) => repo.id === source.repository_id));
    stats.push(["Repos", repos.length], ["Sources", sources.length]);
    stats.push(["Raw", countForSources("rawRecords", sources)], ["Arts", countForSources("arts", sources)]);
  }
  if (kind === "repo") {
    const sources = (state.data.sources || []).filter((source) => source.repository_id === item.id);
    stats.push(["Sources", sources.length], ["Jobs", countForSources("ingestionJobs", sources)]);
    stats.push(["Raw", countForSources("rawRecords", sources)], ["Arts", countForSources("arts", sources)]);
  }
  if (kind === "source") {
    const latestJob = latestSourceJob(item.id);
    stats.push(["Jobs", recordsForSource("ingestionJobs", item.id).length]);
    stats.push(["Latest", latestJob?.status || "none"]);
    stats.push(["Raw", recordsForSource("rawRecords", item.id).length]);
    stats.push(["Arts", recordsForSource("arts", item.id).length]);
    stats.push(["Metadata", recordsForSource("metadata", item.id).length]);
    stats.push(["Rels", recordsForSource("relationships", item.id).length]);
  }
  return `
    <div class="quick-stats">${stats.map(([label, value]) => `
      <div><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>
    `).join("")}</div>
    ${summaryTable(item)}
  `;
}

function countForSources(key, sources) {
  const aggregateField = {
    rawRecords: "raw_records",
    arts: "arts",
    metadata: "metadata",
    relationships: "relationships",
  }[key];
  if (aggregateField && state.data.analytics?.source_counts?.length) {
    const ids = new Set(sources.map((source) => source.id));
    return (state.data.analytics.source_counts || [])
      .filter((source) => ids.has(source.id))
      .reduce((total, source) => total + Number(source[aggregateField] || 0), 0);
  }
  const ids = new Set(sources.map((source) => source.id));
  return (state.data[key] || []).filter((record) => ids.has(record.source_id)).length;
}

function latestSourceJob(sourceId) {
  return recordsForSource("ingestionJobs", sourceId).sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
}

function barLine(label, value, max) {
  const width = Math.round((value / max) * 100);
  return `
    <div class="bar-line">
      <span>${escapeHtml(label)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
      <strong>${value}</strong>
    </div>
  `;
}

function groupCounts(records, keyFn) {
  return records.reduce((acc, record) => {
    const key = keyFn(record);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function selectedSource() {
  if (state.selected.kind !== "source") return null;
  return (state.data.sources || []).find((source) => source.id === state.selected.id);
}

function selectedRepository() {
  const repos = state.data.repositories || [];
  if (state.selected.kind === "repo") {
    return repos.find((repo) => repo.id === state.selected.id) || null;
  }
  if (state.selected.kind === "source") {
    const source = selectedSource();
    return repos.find((repo) => repo.id === source?.repository_id) || null;
  }
  return null;
}

function findSwiftRepository() {
  return (state.data.repositories || []).find((repo) =>
    [repo.name, repo.slug, repo.canonical_url]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes("openstack/swift") || String(value).toLowerCase().includes("swift")),
  );
}

function selectedSources() {
  const sources = state.data.sources || [];
  if (state.selected.kind === "source") {
    return sources.filter((source) => source.id === state.selected.id);
  }
  if (state.selected.kind === "repo") {
    return sources.filter((source) => source.repository_id === state.selected.id);
  }
  if (state.selected.kind === "group") {
    const repoIds = new Set(
      (state.data.repositories || [])
        .filter((repo) => repo.repository_group_id === state.selected.id)
        .map((repo) => repo.id),
    );
    return sources.filter((source) => repoIds.has(source.repository_id));
  }
  return [];
}

function selectedRepositoryIdForSources(sources) {
  if (state.selected.kind === "repo") return state.selected.id;
  const ids = new Set(sources.map((source) => source.repository_id).filter(Boolean));
  return ids.size === 1 ? Array.from(ids)[0] : "";
}

function isExpanded(key) {
  return !state.collapsed.has(key);
}

function toggleExpanded(key) {
  if (state.collapsed.has(key)) state.collapsed.delete(key);
  else state.collapsed.add(key);
}

function sum(records, fn) {
  return records.reduce((total, record) => total + fn(record), 0);
}

function capitalize(value) {
  const text = String(value || "");
  return text ? `${text[0].toUpperCase()}${text.slice(1)}` : "";
}

function sortReviewArts(records = []) {
  const rank = (art) => {
    if (art.review_message_kind === "inline_comment") return 0;
    if (art.review_message_kind === "change_message") return 1;
    if (art.review_message_kind === "change_subject") return 2;
    if (art.automated) return 4;
    return 3;
  };
  return [...records].sort((a, b) => {
    const byKind = rank(a) - rank(b);
    if (byKind !== 0) return byKind;
    const bTime = String(b.source_created_at || b.imported_at || "");
    const aTime = String(a.source_created_at || a.imported_at || "");
    return bTime.localeCompare(aTime);
  });
}

function reviewLocationHtml(art) {
  const bits = [];
  if (art.file_path) bits.push(art.file_path);
  if (art.line !== undefined && art.line !== null && art.line !== "") bits.push(`line ${art.line}`);
  if (art.patch_set !== undefined && art.patch_set !== null && art.patch_set !== "") bits.push(`patch set ${art.patch_set}`);
  return bits.length ? `<div class="mini">${escapeHtml(bits.join(" | "))}</div>` : "";
}

function preview(text, len) {
  return String(text || "").slice(0, len);
}

function linkHtml(url) {
  if (!url) return "";
  const href = escapeAttr(url);
  return `<a href="${href}" target="_blank" rel="noreferrer">${escapeHtml(url)}</a>`;
}

function formatNumber(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toLocaleString() : String(value ?? "");
}

function formatCompactNumber(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return String(value ?? "");
  if (Math.abs(number) >= 1_000_000) return `${roundNumber(number / 1_000_000, 1)}m`;
  if (Math.abs(number) >= 1_000) return `${roundNumber(number / 1_000, 1)}k`;
  return formatNumber(number);
}

function roundNumber(value, digits = 0) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  const factor = 10 ** digits;
  return Math.round(number * factor) / factor;
}

function formatDateTimeCompact(value) {
  const text = String(value || "");
  if (!text) return "unknown";
  const unix = text.match(/^unix:(\d+)$/);
  if (unix) {
    const date = new Date(Number(unix[1]) * 1000);
    if (!Number.isNaN(date.getTime())) return date.toISOString().replace("T", " ").slice(0, 16);
  }
  return text.replace("T", " ").slice(0, 16);
}

function clampNumber(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, number));
}

function formatCell(value) {
  if (typeof value === "number") return formatNumber(value);
  if (/^\d+$/.test(String(value || ""))) return formatNumber(value);
  return preview(String(value ?? ""), 220);
}

function formatPercent(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number) || number <= 0) return "";
  return `${(number * 100).toFixed(1)}%`;
}

function stripJsonScalar(value) {
  const text = String(value ?? "");
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    try {
      return JSON.parse(text);
    } catch {
      return text.slice(1, -1);
    }
  }
  return text;
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function parseJson(value, fallback) {
  if (typeof value !== "string") return value ?? fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("'", "&#39;");
}

function loadLocalConfig() {
  const saved = parseJson(localStorage.getItem("repointel-debug-config"), {});
  state.config = { ...state.config, ...saved };
}

async function loadServerConfig() {
  try {
    const headers = {};
    if (state.config.metadataToken) headers.authorization = `Bearer ${state.config.metadataToken}`;
    const response = await fetch("/api/metadata/console/config", { headers });
    const config = await response.json();
    state.config.repointelProxy = sameOriginPath(state.config.repointelProxy, config.repointelProxy);
    state.config.metadataProxy = sameOriginPath(state.config.metadataProxy, config.metadataCollectionProxy);
    state.config.analyticsAvailable = Boolean(config.analyticsAvailable);
  } catch {
    // Static file usage without the proxy still lets the user set URLs manually.
  }
}

function hydrateConfigInputs() {
  $("#repointelProxy").value = state.config.repointelProxy;
  $("#metadataProxy").value = state.config.metadataProxy;
  $("#repointelToken").value = state.config.repointelToken;
  $("#metadataToken").value = state.config.metadataToken;
  const minCommits = $("#authorDensityMinCommits");
  if (minCommits) minCommits.value = String(state.config.authorDensityMinCommits || 10);
  const minApprovals = $("#reviewerDensityMinApprovals");
  if (minApprovals) minApprovals.value = String(state.config.reviewerDensityMinApprovals || 10);
}

function saveConfig() {
  state.config = {
    repointelProxy: sameOriginPath($("#repointelProxy").value, "/api/repointel"),
    metadataProxy: sameOriginPath($("#metadataProxy").value, "/api/metadata"),
    repointelToken: $("#repointelToken").value.trim(),
    metadataToken: $("#metadataToken").value.trim(),
    analyticsAvailable: state.config.analyticsAvailable,
    authorDensityMinCommits: authorDensityMinCommits(),
    reviewerDensityMinApprovals: reviewerDensityMinApprovals(),
  };
  localStorage.setItem("repointel-debug-config", JSON.stringify(state.config));
  hydrateConfigInputs();
  toast("Configuration saved");
}

function authorDensityMinCommits() {
  const input = $("#authorDensityMinCommits");
  const value = Number(input?.value || state.config.authorDensityMinCommits || 10);
  return Number.isFinite(value) && value >= 1 ? Math.floor(value) : 10;
}

function reviewerDensityMinApprovals() {
  const input = $("#reviewerDensityMinApprovals");
  const value = Number(input?.value || state.config.reviewerDensityMinApprovals || 10);
  return Number.isFinite(value) && value >= 1 ? Math.floor(value) : 10;
}

function sameOriginPath(value, fallback) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return fallback;
  if (/^https?:\/\//i.test(trimmed)) return fallback;
  return trimmed.startsWith("/") ? trimmed.replace(/\/+$/, "") || "/" : fallback;
}

function toast(message, bad = false, detail = "") {
  const stack = $("#toastStack");
  if (!stack) return;
  const node = document.createElement("div");
  node.className = `toast ${bad ? "bad" : ""}`;
  node.innerHTML = `
    <div class="toast-title">${escapeHtml(message)}</div>
    ${detail ? `<div class="toast-detail">${escapeHtml(detail)}</div>` : ""}
  `;
  stack.prepend(node);
  while (stack.children.length > 8) stack.lastElementChild.remove();
  window.setTimeout(() => node.classList.add("show"), 0);
  window.setTimeout(() => {
    node.classList.remove("show");
    window.setTimeout(() => node.remove(), 220);
  }, bad ? 12000 : 8000);
}
