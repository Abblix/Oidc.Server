// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// The lifecycle state of a service key as it moves through generation, activation, retirement and
/// deletion. The transitions themselves are driven by the rotation engine; this contract only names the
/// states so a persistent store and the read seam agree on their meaning.
/// </summary>
public enum KeyLifecycleStatus
{
    /// <summary>
    /// Generated and published for verification, but not yet used for signing. Publishing a key before it
    /// signs (publish-before-sign) gives relying parties time to fetch it, so the first token it signs
    /// already verifies against a key they hold.
    /// </summary>
    Pending,

    /// <summary>The current signing key: within its <c>not_before</c> / <c>not_after</c> window.</summary>
    Active,

    /// <summary>
    /// Past <c>not_after</c>, so it no longer signs, but still published so tokens it already signed keep
    /// verifying until they expire.
    /// </summary>
    Retiring,

    /// <summary>Past <c>delete_after</c>: no live token can reference it, so it is removed from publication.</summary>
    Retired,
}