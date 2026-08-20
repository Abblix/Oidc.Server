// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Azure;

/// <summary>
/// Points the custodian at an Azure Key Vault: which vault and how to authenticate to it, and nothing about which
/// keys to use. Which keys, and therefore whether their private halves ever enter this process, is the placement
/// choice that follows the custodian registration.
/// </summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>The vault URI, e.g. <c>https://my-vault.vault.azure.net/</c>.</summary>
    public required Uri KeyVaultUri { get; set; }

    /// <summary>
    /// Tenant ID of the service principal. When <see cref="TenantId"/>, <see cref="ClientId"/> and
    /// <see cref="ClientSecret"/> are all set the custodian authenticates with a client-secret credential;
    /// leave them blank to fall back to the default Azure credential chain (a managed identity in production,
    /// an Azure CLI sign-in, or the <c>AZURE_TENANT_ID</c> / <c>AZURE_CLIENT_ID</c> / <c>AZURE_CLIENT_SECRET</c>
    /// environment variables). Source the secret from the environment or a secret store, never hardcode it.
    /// </summary>
    public string TenantId { get; set; } = "";

    /// <summary>Application (client) ID of the service principal; see <see cref="TenantId"/>.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Client secret of the service principal; see <see cref="TenantId"/>. Never hardcode it.</summary>
    public string ClientSecret { get; set; } = "";

    /// <summary>
    /// How long a pooled HTTP connection is reused before it is recycled. The Azure SDK keeps one client for the
    /// vault, so recycling connections lets it pick up DNS changes without handler rotation (default 2 minutes,
    /// matching the default IHttpClientFactory handler lifetime).
    /// </summary>
    public TimeSpan PooledConnectionLifetime { get; set; } = TimeSpan.FromMinutes(2);
}
