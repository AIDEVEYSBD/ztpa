-- 0008 — allow 'vertex' as a stored advisory provider
--
-- Google Vertex AI joins Azure AI Foundry as a provider that runs in the
-- customer's own cloud project. Its target (project, location, model) is
-- environment-only, so the only change the store needs is the vocabulary.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.ai_config DROP CONSTRAINT IF EXISTS ai_config_provider_check;
ALTER TABLE ztpa.ai_config ADD CONSTRAINT ai_config_provider_check
    CHECK (provider IN ('auto', 'azure', 'vertex', 'openai', 'anthropic', 'ollama'));
