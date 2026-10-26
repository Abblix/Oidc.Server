// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserInfo;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The scope claims a server answers with: the standard scopes, plus the scopes the tenant each call is handed
/// declares.
/// </summary>
internal static class ScopeClaims
{
    public static IScopeClaimsProvider Of() => new ScopeClaimsProvider(SingleIssuer.ScopeManager());
}
