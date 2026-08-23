// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Records a revocation as a cutoff against the principal, which is one write however many tokens it
/// invalidates.
/// </summary>
/// <param name="cutoffRegistry">Where the cutoff is kept.</param>
/// <param name="logger">Records each cutoff written, which is the only trace a revocation leaves.</param>
/// <param name="options">Supplies how long a cutoff is retained.</param>
/// <param name="clock">Supplies the current moment when the caller names none.</param>
public partial class TokenRevoker(
    ILogger<TokenRevoker> logger,
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
        var now = clock.GetUtcNow();
        var cutoff = before ?? now;

        // The record must outlive every token the cutoff refuses, and the two ends of that are different
        // questions. A cutoff in the past still has to cover the tokens alive today, so retention is
        // measured from now rather than from it. A cutoff in the future is not covered by now at all - it
        // refuses tokens the retention window would already have dropped the record for - so the later of
        // the two anchors it. Without that, a cutoff further ahead than the retention window is a revocation
        // that quietly stops applying before it starts.
        var expiresAt = (cutoff > now ? cutoff : now) + options.Value.RevocationCutoffRetention;

        LogCutoffRecorded(scope, cutoff, expiresAt);

        return cutoffRegistry.SetCutoffAsync(scope, principal, cutoff, expiresAt, cancellationToken);
    }
}
