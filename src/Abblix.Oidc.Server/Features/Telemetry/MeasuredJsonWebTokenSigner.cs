// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Runs signing each token as a stage of the request and records how long it takes into
/// <see cref="OidcMetrics.TokenSigningDuration"/>; a token left unsigned, for want of a key, is not a signing and is
/// neither run as a stage nor recorded.
/// </summary>
/// <param name="inner">The signer the server uses.</param>
/// <param name="instruments">Records the signing into the server's metrics.</param>
internal sealed class MeasuredJsonWebTokenSigner(IJsonWebTokenSigner inner, OidcInstruments instruments)
    : IJsonWebTokenSigner
{
    /// <inheritdoc />
    public async Task<string> SignAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        CancellationToken cancellationToken = default)
    {
        if (signingKey is null)
            return await inner.SignAsync(token, signingKey, cancellationToken);

        var started = Stopwatch.GetTimestamp();
        var jws = await StageObservation.RunAsync(
            TelemetryStages.Signing,
            () => inner.SignAsync(token, signingKey, cancellationToken),
            StageObservation.NeverRefused);

        // Read after signing: the signer settles the algorithm from the key and the header together and writes it
        // into the header, so before the call the header may name none or another one.
        instruments.TokenSigned(token.Header.Algorithm ?? TelemetryTags.Other, Stopwatch.GetElapsedTime(started));
        return jws;
    }

    /// <inheritdoc />
    public Task<JwtValidationError?> ValidateAsync(
        string[] jwt,
        JsonWebTokenHeader header,
        IAsyncEnumerable<JsonWebKey> signingKeys,
        CancellationToken cancellationToken = default)
        => inner.ValidateAsync(jwt, header, signingKeys, cancellationToken);
}
