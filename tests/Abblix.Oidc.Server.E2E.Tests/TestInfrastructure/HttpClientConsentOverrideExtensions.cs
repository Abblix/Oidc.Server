// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestStubs;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Test helpers that pin a per-test consent override onto an <see cref="HttpClient"/> by
/// adding the <see cref="TestConsentOverrideMiddleware.HeaderName"/> header to its default
/// request headers. The returned <see cref="IDisposable"/> removes the header on dispose,
/// so a <c>using</c> block scopes the override exactly to the requests issued inside it.
/// </summary>
public static class HttpClientConsentOverrideExtensions
{
    /// <summary>
    /// Pins a consent override onto <paramref name="client"/> until the returned scope is
    /// disposed.
    /// <list type="bullet">
    /// <item><description><c>null</c>: override is active and the granted AD is null --
    /// provider has "no AD opinion", pipeline falls back to the request's value
    /// (equivalent to no override semantically, but the header still travels for parity).</description></item>
    /// <item><description>empty <see cref="JsonArray"/>: provider says "user denied every
    /// entry" -- pipeline fails with <c>access_denied</c> when the request carried entries.</description></item>
    /// <item><description>non-empty: provider says "consented to this narrowed set" --
    /// pipeline emits this exact value byte-exact into the access token.</description></item>
    /// </list>
    /// </summary>
    public static IDisposable UseConsentOverride(this HttpClient client, JsonArray? grantedAuthorizationDetails)
    {
        var headerValue = grantedAuthorizationDetails?.ToJsonString() ?? "null";
        client.DefaultRequestHeaders.Remove(TestConsentOverrideMiddleware.HeaderName);
        client.DefaultRequestHeaders.Add(TestConsentOverrideMiddleware.HeaderName, headerValue);
        return new RemoveHeaderOnDispose(client);
    }

    private sealed class RemoveHeaderOnDispose(HttpClient client) : IDisposable
    {
        public void Dispose() =>
            client.DefaultRequestHeaders.Remove(TestConsentOverrideMiddleware.HeaderName);
    }
}
