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

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// The end user's refusal on the login page: a pending authorization request the user signed in for and refused is
/// answered with a consent that grants nothing, which the server tells the client as access_denied (OpenID Connect Core
/// 1.0 section 3.1.2.6, "If the End-User denies the request").
/// </summary>
/// <remarks>
/// The suite's modules where the user rejects the request expect that error back at the client; every other request is
/// granted as before.
/// </remarks>
public sealed class RefusedAuthorizations(IUserConsentsProvider inner, TimeProvider clock) : IUserConsentsProvider
{
    private static readonly ConcurrentDictionary<string, bool> Refused = new(StringComparer.Ordinal);

    /// <summary>
    /// Records the end user's refusal of the pending authorization request <paramref name="requestUri"/>.
    /// </summary>
    public static void Refuse(string requestUri) => Refused[requestUri] = true;

    public Task<UserConsents> GetUserConsentsAsync(
        TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
    {
        // The login page names the pending request by the request_uri it was sent there with, which the authorization
        // request is resolved from when the browser returns from the login page
        if (request.RequestUri?.OriginalString is { } requestUri && Refused.TryRemove(requestUri, out _))
            return Task.FromResult(new UserConsents { GivenAt = clock.GetUtcNow() });

        return inner.GetUserConsentsAsync(tenant, request, authSession);
    }
}
