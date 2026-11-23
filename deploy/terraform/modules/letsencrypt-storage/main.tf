locals {
  public_access = length(var.allowed_ip_ranges) > 0
}

# Holds only short-lived Let's Encrypt HTTP-01 tokens. Served to the ACME server
# through the Application Gateway port-80 listener over the `web` private endpoint.
resource "azurerm_storage_account" "this" {
  name                            = var.name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = local.public_access
  # Kept enabled because the azurerm provider polls the blob data plane with the
  # account key during create (same as DEPA-inferencing). Clients use Entra ID
  # (`--auth-mode login`); OAuth is the portal/CLI default.
  shared_access_key_enabled       = true
  default_to_oauth_authentication = true
  tags                            = var.tags

  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
    ip_rules       = [for c in var.allowed_ip_ranges : trimsuffix(c, "/32")]
  }
}

resource "azurerm_storage_account_static_website" "this" {
  storage_account_id = azurerm_storage_account.this.id
  index_document     = "index.html"
  error_404_document = "404.html"
}

resource "azurerm_role_assignment" "blob_writer" {
  for_each = toset(var.blob_writer_principal_ids)

  scope                = azurerm_storage_account.this.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
}

resource "azurerm_private_dns_zone" "web" {
  name                = "privatelink.web.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "web" {
  for_each = var.endpoints

  name                  = "${var.name}-web-${each.key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.web.name
  virtual_network_id    = each.value.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  for_each = var.endpoints

  name                  = "${var.name}-blob-${each.key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = each.value.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_endpoint" "web" {
  name                = "${var.name}-web-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.endpoints["primary"].subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.name}-web-psc"
    private_connection_resource_id = azurerm_storage_account.this.id
    is_manual_connection           = false
    subresource_names              = ["web"]
  }

  private_dns_zone_group {
    name                 = "web"
    private_dns_zone_ids = [azurerm_private_dns_zone.web.id]
  }
}

resource "azurerm_private_endpoint" "blob" {
  for_each = var.endpoints

  name                = "${var.name}-blob-${each.key}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = each.value.subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.name}-blob-${each.key}-psc"
    private_connection_resource_id = azurerm_storage_account.this.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }
}
