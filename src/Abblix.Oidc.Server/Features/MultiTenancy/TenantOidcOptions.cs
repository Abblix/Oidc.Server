// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The settings one tenant's requests are served with, as the checks of the server's settings judge them: the
/// server's own, with each setting the tenant declares taken from the tenant.
/// </summary>
/// <remarks>
/// A type of its own rather than a name of its own tells a check judging what the server's own settings leave to
/// the tenants - the keys - which settings it is looking at. The name stays the default one, which a host's own
/// checks, bound to that name, need in order to judge a tenant's settings at all.
/// </remarks>
internal sealed record TenantOidcOptions : OidcOptions
{
    /// <summary>
    /// Starts from the server's own settings.
    /// </summary>
    /// <param name="server">The server's own settings.</param>
    public TenantOidcOptions(OidcOptions server)
        : base(server)
    {
    }
}
