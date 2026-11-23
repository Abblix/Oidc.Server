// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RateLimiting;

namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// The budget of revocation requests a caller is charged to, and the refusal of a request that finds it spent.
/// </summary>
internal static class RevocationBudget
{
    /// <summary>
    /// Names the budget this caller's request is charged to, or null when it is charged to none.
    /// </summary>
    /// <remarks>
    /// A request in a public client's name is charged to that name paired with the address it came from, so
    /// that one sender's flood cannot reach the client's other users. With no address, nothing is charged:
    /// the only key left is the name alone, which a stranger could spend to silence that client's logout.
    /// <para>
    /// The last arm cannot be entered while <see cref="ClientInfo.ClientType"/> derives its answer from the
    /// authentication method and has only these two to give.
    /// </para>
    /// </remarks>
    /// <param name="clientInfo">The client the request authenticated as.</param>
    /// <param name="requestInfoProvider">Names the address the request came from.</param>
    /// <param name="unnamedSource">Told of a public client's request from no address, which no budget is charged
    /// for, so the operator learns the budget then refuses none of them.</param>
    public static (string ClientId, string? Source)? KeyFor(
        ClientInfo clientInfo,
        IRequestInfoProvider requestInfoProvider,
        UnnamedSourceNotice unnamedSource)
        => clientInfo.ClientType switch
        {
            ClientType.Confidential => (clientInfo.ClientId, (string?)null),
            ClientType.Public => requestInfoProvider.SourceName() is { } source
                ? (clientInfo.ClientId, (string?)source)
                : ChargedToNone(unnamedSource),
            _ => throw new InvalidOperationException(
                $"Unknown {nameof(ClientType)} {clientInfo.ClientType} for client {clientInfo.ClientId}"),
        };

    /// <summary>
    /// The refusal of a request whose budget <paramref name="lease"/> found spent, with the wait the limiter names.
    /// </summary>
    /// <param name="lease">The lease the limiter did not grant.</param>
    public static TooManyRequestsError Spent(RateLimitLease lease)
        => new(
            "Too many revocation requests from this client",
            lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : null,
            CallerRateLimiters.Revocation);

    private static (string ClientId, string? Source)? ChargedToNone(UnnamedSourceNotice unnamedSource)
    {
        unnamedSource.Report(CallerRateLimiters.Revocation);
        return null;
    }
}
