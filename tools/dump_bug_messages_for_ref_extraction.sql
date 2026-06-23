\pset tuples_only on
\pset format unaligned

WITH repos AS (
  SELECT
    id AS repository_id,
    doc->>'name' AS repository_name,
    doc->>'slug' AS repository_slug,
    doc->>'canonical_url' AS repository_url
  FROM repointel_records
  WHERE collection = 'repositories'
),
authors AS (
  SELECT
    id AS author_id,
    doc->>'display_name' AS author_name,
    doc->>'username' AS author_username,
    doc->>'external_author_id' AS external_author_id
  FROM repointel_records
  WHERE collection = 'authors'
),
bug_raw AS (
  SELECT
    id AS raw_record_id,
    doc->>'repository_id' AS repository_id,
    doc->'payload'->>'id' AS bug_id,
    doc->'payload'->>'title' AS bug_title,
    doc->'payload'->>'status' AS bug_status,
    doc->'payload'->>'importance' AS bug_importance,
    doc->'payload'->>'date_created' AS bug_created_at,
    doc->'payload'->>'date_last_updated' AS bug_last_updated_at,
    doc->'payload'->>'date_last_message' AS bug_last_message_at,
    doc->'payload'->>'web_link' AS bug_url
  FROM repointel_records
  WHERE collection = 'raw-records'
    AND doc->>'record_type' = 'launchpad_bug'
)
SELECT json_build_object(
  'repository_id', a.doc->>'repository_id',
  'repository_name', COALESCE(r.repository_name, a.doc->>'repository_id'),
  'repository_slug', COALESCE(NULLIF(r.repository_slug, ''), r.repository_name, a.doc->>'repository_id'),
  'repository_url', r.repository_url,
  'bug_id', COALESCE(NULLIF(a.doc->>'context_external_id', ''), br.bug_id),
  'bug_url', br.bug_url,
  'bug_title', br.bug_title,
  'bug_status', br.bug_status,
  'bug_importance', br.bug_importance,
  'bug_created_at', br.bug_created_at,
  'bug_last_updated_at', br.bug_last_updated_at,
  'bug_last_message_at', br.bug_last_message_at,
  'bug_raw_record_id', a.doc->>'raw_record_id',
  'art_id', a.id,
  'art_external_id', a.doc->>'external_id',
  'bug_message_kind',
    CASE
      WHEN a.doc->>'external_id' LIKE 'launchpad-bug-%-description' THEN 'original'
      ELSE 'comment'
    END,
  'message_created_at', COALESCE(a.doc->>'source_created_at', a.doc->>'created_at', ''),
  'message_url', COALESCE(a.doc->>'url', ''),
  'author_id', a.doc->>'author_id',
  'author_name', au.author_name,
  'author_username', au.author_username,
  'external_author_id', au.external_author_id,
  'body', COALESCE(a.doc->>'body', '')
)::text
FROM repointel_records a
LEFT JOIN repos r ON r.repository_id = a.doc->>'repository_id'
LEFT JOIN bug_raw br ON br.raw_record_id = a.doc->>'raw_record_id'
LEFT JOIN authors au ON au.author_id = a.doc->>'author_id'
WHERE a.collection = 'arts'
  AND a.doc->>'type' = 'bug_message'
  AND COALESCE(a.doc->>'body', '') <> '';
