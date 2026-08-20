// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation that checks revocation against <see cref="OidcOptions.RevokedInitialAccessTokenSubjects"/>.
/// For production use with large or dynamic revocation lists, replace with a database- or cache-backed implementation.
/// </summary>
/// <param name="options">OIDC configuration containing the set of revoked token identifiers.</param>
public class InitialAccessTokenRevocationProvider(IOptionsMonitor<OidcOptions> options)
    : IInitialAccessTokenRevocationProvider
{
    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(string subject)
        => Task.FromResult(options.CurrentValue.RevokedInitialAccessTokenSubjects.Contains(subject));
}
