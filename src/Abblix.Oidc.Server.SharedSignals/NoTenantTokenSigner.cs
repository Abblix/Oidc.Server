// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The token signer of the transmitter resolved where no tenant is served: a token is signed with its issuing
/// tenant's keys, so every call is refused rather than signed with keys no tenant's receivers trust.
/// </summary>
internal sealed class NoTenantTokenSigner : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException(
            "A part of the Shared Signals transmitter (here its token signer, which signs with the issuing tenant's "
            + "keys) was resolved where no tenant was served. Resolve the transmitter's parts in the request or "
            + "tenant scope of the tenant they serve, rather than keeping one across requests.");
}
