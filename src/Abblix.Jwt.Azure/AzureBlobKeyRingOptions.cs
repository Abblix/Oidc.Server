// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Azure;

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
