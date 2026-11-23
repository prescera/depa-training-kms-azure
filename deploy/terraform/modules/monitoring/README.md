# monitoring

Alerting for a DC public gateway:
- Metric alert on Application Gateway `UnhealthyHostCount` for the ledger backend
  (ledger down, private endpoint unapproved, backend TLS trust broken).
- Workspace-based Application Insights + **standard web test** against the public
  endpoint (default for the KMS: the OIDC discovery document) from several
  regions, validating HTTP 200, optional content match, TLS validity and a
  minimum remaining certificate lifetime (default 20 days, so a failed Let's
  Encrypt renewal pages well before expiry), with a location-availability alert.
- Optional e-mail action group; `additional_action_group_ids` for existing
  routing (PagerDuty, Teams...). Alerts are only created when at least one
  action target exists; the web test always runs.

Inputs: `application_gateway_id`, `ledger_backend_settings_pool`,
`log_analytics_workspace_id`, `public_check`, `alert_email_addresses`,
`additional_action_group_ids`, `severity`. Outputs: `action_group_id`,
`application_insights_id`, `web_test_id`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/monitoring`; keep the `.tf` files identical.
