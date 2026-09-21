// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Stops looking at credentials from a source whose authentications keep failing, and counts each failure
/// against the address it came from.
/// </summary>
/// <remarks>
/// Verifying a credential is not free: a client assertion is a signature this server checks before it can say
/// the credential is wrong, so a sender that never authenticates successfully buys one verification per request
/// for as long as it cares to send them. No budget charged to a client can reach such a sender, because it
/// never proves to be one.
/// <para>
/// It wraps the authenticator rather than standing in each endpoint, so every endpoint that authenticates a
/// client is covered by one decision - the token endpoint most of all, since every deployment exposes it while
/// few expose introspection, and a failing credential costs the same at either.
/// </para>
/// <para>
/// The budget is off until a deployment turns it on, and then this decorator refuses nothing until a source has
/// spent it: <see cref="AuthenticationFailureBudget"/> says what an address has to mean for that to be safe.
/// </para>
/// </remarks>
/// <param name="logger">Records a refusal, naming the address it was charged to.</param>
/// <param name="inner">The authenticator whose credentials this one decides whether to look at.</param>
/// <param name="budget">The failures one source address gets.</param>
internal sealed partial class ThrottledClientAuthenticator(
    ILogger<ThrottledClientAuthenticator> logger,
    IClientAuthenticator inner,
    AuthenticationFailureBudget budget) : IClientAuthenticator
{
    /// <inheritdoc />
    public IEnumerable<string> ClientAuthenticationMethodsSupported => inner.ClientAuthenticationMethodsSupported;

    /// <inheritdoc />
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        if (budget.RefuseIfSpent() is { } refusal)
        {
            LogSourceRefused(Sanitized.Value(budget.Source));
            throw new TooManyAuthenticationFailuresException(refusal.RetryAfter);
        }

        var clientInfo = await inner.TryAuthenticateClientAsync(request);
        if (clientInfo == null)
            budget.RecordFailure();

        return clientInfo;
    }
}
