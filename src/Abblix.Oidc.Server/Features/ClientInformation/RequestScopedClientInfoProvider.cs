// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The clients one request names, each found once however many of its steps ask (Decorator).
/// </summary>
/// <remarks>
/// A request names its client at several steps - client authentication, the per-client rule on pushed requests, the
/// request object or request_uri it arrives with, the client validation, the response it is answered with - and each
/// would otherwise ask the store, and fetch a client metadata document the store does not hold, again. The first answer
/// for a tenant and a client identifier, found or absent, answers every later step.
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
internal sealed class RequestScopedClientInfoProvider(IClientInfoProvider inner)
    : IClientInfoProvider
{
    private readonly ConcurrentDictionary<(string TenantId, string ClientId), Task<Result<ClientInfo, ClientAbsence>>>
        _answers = new();

    /// <inheritdoc />
    public Task<Result<ClientInfo, ClientAbsence>> FindClientAsync(TenantDefinition tenant, string clientId)
    {
        return _answers.GetOrAdd((tenant.Id, clientId), _ => inner.FindClientAsync(tenant, clientId));
    }

    /// <summary>
    /// The refusal of a request whose client authentication failed, where a client the request named could not be had
    /// for now (<see cref="ClientAbsenceReason.TemporarilyUnavailable"/>): the client the credential would have been
    /// checked against is unknown for a reason that may pass, so the failure says nothing about the credential. Null
    /// where every client the request named was found or refused.
    /// </summary>
    /// <remarks>
    /// Asked of the answers the authentication already received, so it fetches nothing. Experimental, as the reason it
    /// reads is: draft-ietf-oauth-client-id-metadata-document-03 section 6.1 answers such a request at the token and
    /// pushed authorization request endpoints "for a transient failure, an HTTP 503 status code".
    /// </remarks>
    public ClientTemporarilyUnavailableError? UnavailableClientRefusal()
    {
        foreach (var answer in _answers.Values)
        {
            if (answer.IsCompletedSuccessfully &&
                answer.Result.TryGetFailure(out var absence) &&
                absence.Reason == ClientAbsenceReason.TemporarilyUnavailable)
            {
                return UnavailableClient;
            }
        }

        return null;
    }

    private static ClientTemporarilyUnavailableError UnavailableClient { get; } =
        new("The client metadata document could not be retrieved for now");
}
