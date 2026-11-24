// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Stops looking at credentials from a source whose authentications keep failing, and counts each failure
/// against the address it came from.
/// </summary>
/// <remarks>
/// Verifying a credential costs a signature check before this server can say the credential is wrong, and no
/// budget charged to a client reaches a sender that never proves to be one.
/// <para>
/// It wraps the authenticator rather than standing in each endpoint, so one decision covers every endpoint
/// that authenticates a client, the token endpoint included.
/// </para>
/// <para>
/// The budget is off until a deployment turns it on: <see cref="AuthenticationFailureBudget"/> says what an
/// address has to mean for that to be safe.
/// </para>
/// </remarks>
/// <param name="logger">Records a refusal, naming the address it was charged to.</param>
/// <param name="inner">The authenticator whose credentials this one decides whether to look at.</param>
/// <param name="serviceProvider">Resolves the failures one source address gets at the first authentication rather
/// than when this authenticator is built: the checks of the server's settings ask it which methods it offers, and a
/// host of the server's core registers what the budget reads the source address with only to serve requests.</param>
/// <param name="unnamedSource">Says, once, that a request arrived from no address and so went uncounted.</param>
internal sealed partial class ThrottledClientAuthenticator(
    ILogger<ThrottledClientAuthenticator> logger,
    IClientAuthenticator inner,
    IServiceProvider serviceProvider,
    UnnamedSourceNotice unnamedSource) : IClientAuthenticator
{
    private readonly Lazy<AuthenticationFailureBudget> _budget =
        new(serviceProvider.GetRequiredService<AuthenticationFailureBudget>);

    /// <inheritdoc />
    public IEnumerable<string> ClientAuthenticationMethodsSupported => inner.ClientAuthenticationMethodsSupported;

    /// <inheritdoc />
    public Task<IEnumerable<string>> FindPresentedCredentialsAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients)
        => inner.FindPresentedCredentialsAsync(tenant, request, clients);

    /// <inheritdoc />
    public async Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients)
    {
        var budget = _budget.Value;
        var source = budget.Source;
        if (source is null)
            unnamedSource.Report(CallerRateLimiters.AuthenticationFailures);

        if (budget.RefuseIfSpent(source) is { } refusal)
        {
            LogSourceRefused(Sanitized.Value(source));
            throw new TooManyAuthenticationFailuresException(refusal);
        }

        // A request using more than one method is refused before any credential is looked at, as a repeated
        // Authorization header is refused before the authenticator, so it spent nothing the budget prices
        var result = await inner.TryAuthenticateClientAsync(tenant, request, clients);
        if (!result.TryGetSuccess(out _) && result.GetFailure() is not MoreThanOneClientAuthenticationMethodError)
            budget.RecordFailure(source);

        return result;
    }
}
