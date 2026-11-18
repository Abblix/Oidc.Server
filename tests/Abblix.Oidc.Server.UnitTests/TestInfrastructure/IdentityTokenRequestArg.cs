// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Matches the ID token request a double is handed by what it is for and what it binds, so a setup names the values
/// it cares about and leaves the session and the context to any value unless it names them.
/// </summary>
public static class IdentityTokenRequestArg
{
    /// <summary>
    /// A request for <paramref name="client"/> binding exactly the values given; <paramref name="session"/> and
    /// <paramref name="context"/> are compared only where given.
    /// </summary>
    public static IdentityTokenRequest For(
        ClientInfo client,
        bool includeUserClaims,
        string? authorizationCode,
        string? accessToken,
        string? state,
        AuthSession? session,
        AuthorizationContext? context)
        => Match.Create<IdentityTokenRequest>(request =>
            IsFor(request, client, session, context) &&
            Binds(request, includeUserClaims, authorizationCode, state) &&
            request.AccessToken == accessToken);

    private static bool IsFor(
        IdentityTokenRequest request, ClientInfo client, AuthSession? session, AuthorizationContext? context)
        => request.ClientInfo == client && HasSession(request, session) && HasContext(request, context);

    private static bool HasSession(IdentityTokenRequest request, AuthSession? session)
        => session is null || request.AuthSession == session;

    private static bool HasContext(IdentityTokenRequest request, AuthorizationContext? context)
        => context is null || request.AuthContext == context;

    private static bool Binds(
        IdentityTokenRequest request, bool includeUserClaims, string? authorizationCode, string? state)
        => request.IncludeUserClaims == includeUserClaims &&
           request.AuthorizationCode == authorizationCode &&
           request.State == state;
}
