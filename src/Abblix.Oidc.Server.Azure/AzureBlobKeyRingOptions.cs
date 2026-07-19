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
/// Points the key ring at an Azure Blob Storage container, one blob per key.
/// </summary>
/// <remarks>
/// Blob rather than a Key Vault secret, though the vault is already there: a secret write has no conditional
/// create, so two pods minting the same period would both succeed and each publish its own key. A blob upload
/// takes <c>If-None-Match: *</c>, which is the insert-if-absent the ring needs.
/// </remarks>
public sealed class AzureBlobKeyRingOptions
{
    /// <summary>
    /// The blob service endpoint, for example <c>https://myaccount.blob.core.windows.net</c>. The credential is
    /// the one the custodian already uses, so no second identity is configured.
    /// </summary>
    public required Uri ServiceUri { get; set; }

    /// <summary>The container holding the ring. It is created on first use if it does not exist.</summary>
    public string Container { get; set; } = "oidc-keyring";
}
