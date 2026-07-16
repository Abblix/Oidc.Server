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

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Points the custodian at a HashiCorp Vault / OpenBao Transit secrets engine. The keys themselves live inside
/// Transit as non-exportable keys, so their private halves never reach this process; the custodian addresses
/// each key by its <c>kid</c>, which is the Transit key name the host publishes as the key's identifier.
/// </summary>
public sealed class VaultTransitOptions
{
    /// <summary>Base URL of the Vault / OpenBao server, e.g. <c>http://127.0.0.1:8200</c>.</summary>
    public string Address { get; set; } = "http://127.0.0.1:8200";

    /// <summary>
    /// Auth token presented as the <c>X-Vault-Token</c> header. Source it from the environment or a secret
    /// store, never hardcode it: dev mode uses a well-known root token, while production authenticates through
    /// AppRole or Kubernetes and mints a short-lived token instead.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>Mount path of the Transit engine (the default mount is <c>transit</c>).</summary>
    public string TransitMount { get; set; } = "transit";

    /// <summary>Name of the Transit key used to sign tokens; also the published signing key's <c>kid</c>.</summary>
    public string SigningKeyName { get; set; } = "oidc-sign";

    /// <summary>Name of the Transit key used to unwrap encrypted-token CEKs; also the published encryption key's <c>kid</c>.</summary>
    public string EncryptionKeyName { get; set; } = "oidc-enc";
}
