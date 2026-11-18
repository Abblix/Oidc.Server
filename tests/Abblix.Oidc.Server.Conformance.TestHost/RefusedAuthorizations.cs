// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The end user's refusal on the login page: every authorization request of a session the user signed in to by
/// refusing is answered with a consent that grants nothing, which the server tells the client as access_denied (OpenID
/// Connect Core 1.0 section 3.1.2.6, "If the End-User denies the request").
/// </summary>
/// <remarks>
/// The suite's modules where the user rejects the request expect that error back for each of their clients, the later
/// ones reaching the server in the same browser session without a login page; every other session is granted as before.
/// </remarks>
public sealed class RefusedAuthorizations(IUserConsentsProvider inner, TimeProvider clock) : IUserConsentsProvider
{
    private static readonly ConcurrentDictionary<string, bool> RefusingSessions = new(StringComparer.Ordinal);

    /// <summary>
    /// Records that the end user refuses every request of the session <paramref name="sessionId"/>.
    /// </summary>
    public static void RefuseIn(string sessionId) => RefusingSessions[sessionId] = true;

    public Task<UserConsents> GetUserConsentsAsync(
        TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
    {
        if (RefusingSessions.ContainsKey(authSession.SessionId))
            return Task.FromResult(new UserConsents { GivenAt = clock.GetUtcNow() });

        return inner.GetUserConsentsAsync(tenant, request, authSession);
    }
}
