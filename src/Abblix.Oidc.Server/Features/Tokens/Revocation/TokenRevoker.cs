// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Records a revocation as a cutoff against the principal, which is one write however many tokens it
/// invalidates.
/// </summary>
/// <param name="cutoffRegistry">Where the cutoff is kept.</param>
/// <param name="options">Supplies how long a cutoff is retained.</param>
/// <param name="clock">Supplies the current moment when the caller names none.</param>
public class TokenRevoker(
    IRevocationCutoffRegistry cutoffRegistry,
    IOptions<OidcOptions> options,
    TimeProvider clock) : ITokenRevoker
{
    /// <inheritdoc />
    public Task RevokeSubjectAsync(
        string subject, DateTimeOffset? before = null, CancellationToken cancellationToken = default)
        => RevokeAsync(RevocationScope.Subject, subject, before, cancellationToken);

    /// <inheritdoc />
    public Task RevokeSessionAsync(
        string sessionId, DateTimeOffset? before = null, CancellationToken cancellationToken = default)
        => RevokeAsync(RevocationScope.Session, sessionId, before, cancellationToken);

    private Task RevokeAsync(
        RevocationScope scope, string principal, DateTimeOffset? before, CancellationToken cancellationToken)
    {
        var cutoff = before ?? clock.GetUtcNow();

        // Retention runs from now rather than from the cutoff, because a caller revoking retroactively still
        // needs the record to outlive the tokens alive today - dating it from a cutoff in the past would
        // expire the record early, or immediately.
        var expiresAt = clock.GetUtcNow() + options.Value.RevocationCutoffRetention;

        return cutoffRegistry.SetCutoffAsync(scope, principal, cutoff, expiresAt, cancellationToken);
    }
}
