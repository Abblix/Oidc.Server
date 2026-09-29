// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Revocation;

// The feature is marked experimental for its consumers, and the sample is written as one of them.
#pragma warning disable ABXMT001

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting how work of one tenant runs outside a request.
/// </summary>
/// <remarks>
/// The sample is a method body, so the wrapper is a method taking the names it calls into.
/// </remarks>
internal static class TenantScopeSample
{
    internal static async Task RevokeAsync(
        ITenantCatalog catalog, ITokenRevoker tokenRevoker, string subject, CancellationToken cancellationToken)
    {
        // <sample>
        var tenant = await catalog.FindByIdAsync("acme", cancellationToken)
            ?? throw new InvalidOperationException("No tenant is registered under the id acme.");

        using (TenantScope.Enter(tenant))
            await tokenRevoker.RevokeSubjectAsync(subject, cancellationToken: cancellationToken);
        // </sample>
    }
}
