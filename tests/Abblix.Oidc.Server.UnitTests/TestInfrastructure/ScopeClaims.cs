// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The scope claims a server answers with: the standard scopes, plus whatever a test declares as the host would.
/// </summary>
internal static class ScopeClaims
{
    public static IScopeClaimsProvider Of(params ScopeDefinition[] hostScopes)
        => new ScopeClaimsProvider(new ScopeManager(
            SingleIssuer.SettingsOf(Options.Create(new OidcOptions { Scopes = hostScopes })),
            new SingleIssuerLocal<Dictionary<string, ScopeDefinition>>()));
}
