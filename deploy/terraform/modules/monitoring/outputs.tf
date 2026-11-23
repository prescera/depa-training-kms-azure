output "action_group_id" {
  description = "ID of the created e-mail action group (null when no e-mail receivers)."
  value       = one(azurerm_monitor_action_group.email[*].id)
}

output "application_insights_id" {
  description = "ID of the Application Insights component hosting the web test."
  value       = azurerm_application_insights.this.id
}

output "web_test_id" {
  description = "ID of the public endpoint availability test."
  value       = azurerm_application_insights_standard_web_test.public.id
}
