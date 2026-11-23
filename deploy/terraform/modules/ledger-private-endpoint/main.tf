locals {
  ledger_fqdn = "${var.ledger_name}.confidential-ledger.azure.com"
}

# Connections are manual: the PLS owner approves each one on the ledger's Private
# Link Service before traffic flows.
resource "azurerm_private_endpoint" "this" {
  for_each = var.endpoints

  name                = "${var.ledger_name}-${each.key}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = each.value.subnet_id
  tags                = var.tags

  private_service_connection {
    name                              = "${var.ledger_name}-${each.key}-psc"
    private_connection_resource_alias = var.private_link_service_alias
    is_manual_connection              = true
    request_message                   = "DEPA ${var.ledger_name} (${each.key})"
  }
}

# A zone named after the single ledger FQDN (apex record) overrides resolution
# for this ledger only; a zone for the whole confidential-ledger.azure.com
# domain would break every other ledger resolved from the linked VNets.
resource "azurerm_private_dns_zone" "ledger" {
  name                = local.ledger_fqdn
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each = var.endpoints

  name                  = "${var.ledger_name}-${each.key}-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.ledger.name
  virtual_network_id    = each.value.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_dns_a_record" "ledger" {
  name                = "@"
  zone_name           = azurerm_private_dns_zone.ledger.name
  resource_group_name = var.resource_group_name
  ttl                 = 300
  records             = sort([for pe in azurerm_private_endpoint.this : pe.private_service_connection[0].private_ip_address])
  tags                = var.tags
}
