// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The clients one request names, each found once however many of its steps ask (Decorator).
/// </summary>
/// <remarks>
/// An authorization request names its client at several steps - the per-client rule on pushed requests, the request
/// object or request_uri it arrives with, the client validation, the response it is answered with - and each would
/// otherwise ask the store, and fetch a client metadata document the store does not hold, again. The first answer for
/// a tenant and a client identifier, found or absent, answers every later step.
/// <para>
/// Its lifetime is the one its creator gives it: a handler creates one for the request it serves and passes it on, and
/// it is never registered in the container. A verdict on a client metadata document therefore dies with the request
/// that reached it, and the next request asks again: draft-ietf-oauth-client-id-metadata-document section 6.2 has the
/// server "MUST NOT cache error responses" and "MUST NOT cache documents which are invalid or malformed", which a
/// verdict held by the one request that judged it does not do, and lets the server take "other measures to avoid
/// repeatedly fetching a Client ID Metadata Document URL".
/// </para>
/// </remarks>
/// <param name="inner">The store the clients are found in.</param>
/// <param name="known">A client the request already established, as the pushed authorization request endpoint
/// authenticates its client before anything else, answered without asking the store.</param>
internal sealed class RequestScopedClientInfoProvider(IClientInfoProvider inner, ClientInfo? known = null)
    : IClientInfoProvider
{
    private readonly ConcurrentDictionary<(string TenantId, string ClientId), Task<Result<ClientInfo, ClientAbsence>>>
        _answers = new();

    /// <inheritdoc />
    public Task<Result<ClientInfo, ClientAbsence>> FindClientAsync(TenantDefinition tenant, string clientId)
    {
        if (known is not null && string.Equals(known.ClientId, clientId, StringComparison.Ordinal))
            return Task.FromResult<Result<ClientInfo, ClientAbsence>>(known);

        return _answers.GetOrAdd((tenant.Id, clientId), _ => inner.FindClientAsync(tenant, clientId));
    }
}
