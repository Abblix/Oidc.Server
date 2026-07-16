// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Points the custodian at an Azure Key Vault. The keys are software- or HSM-protected keys whose private half
/// never leaves the vault; this process only sends bytes to sign or decrypt and receives the result. The
/// custodian addresses each key by its <c>kid</c>, which is the Key Vault key name the host publishes.
/// </summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>The vault URI, e.g. <c>https://my-vault.vault.azure.net/</c>.</summary>
    public string KeyVaultUri { get; set; } = "";

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

    /// <summary>Name of the Key Vault key used to sign tokens; also the published signing key's <c>kid</c>.</summary>
    public string SigningKeyName { get; set; } = "oidc-sign";

    /// <summary>Name of the Key Vault key used to unwrap encrypted-token CEKs; also the published encryption key's <c>kid</c>.</summary>
    public string EncryptionKeyName { get; set; } = "oidc-enc";
}
