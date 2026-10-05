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
/// Records how long signing each token takes into <see cref="OidcMetrics.TokenSigningDuration"/>.
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
        var started = Stopwatch.GetTimestamp();
        var jws = await inner.SignAsync(token, signingKey, cancellationToken);

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
