// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// What Shared Signals adds to key resolution: the "jwks_uri" a transmitter advertises about itself.
/// </summary>
/// <remarks>
/// The family word is in the method name rather than only in the namespace because the type extended
/// here belongs to another package, and several packages hang their own vocabulary off it - the same
/// reason <c>RegisterSharedSignalsEvents</c>, <c>RegisterCaepEvents</c> and <c>RegisterRiscEvents</c>
/// each carry theirs.
/// </remarks>
public static class JwksKeyResolutionOptionsExtensions
{
    /// <summary>
    /// Records the transmitter's issuer and the JWK Set it advertises, so events it signs verify.
    /// </summary>
    /// <remarks>
    /// Called when the configuration document has been read, not when the host is composed - a
    /// receiver learns both values over the network, and the map it writes into is safe to write
    /// while resolution reads it.
    /// <para>
    /// It exists so no receiver has to copy the pair out by hand. The two mistakes that copy invites
    /// are silent and identical from the outside: taking the advertised address on faith when SSF
    /// 1.0 Section 7.1 leaves "jwks_uri" out of the REQUIRED set, and comparing the issuer some way
    /// of its own. Both end at the well-known convention - a document that, for a transmitter, is
    /// very likely not its key set at all - so a signature stops verifying and the reason reads as
    /// forgery rather than as wiring.
    /// </para>
    /// </remarks>
    /// <param name="options">Where key sets live.</param>
    /// <param name="transmitter">The configuration document just read from the transmitter.</param>
    /// <returns>The same options, so several transmitters read as a list.</returns>
    /// <exception cref="InvalidOperationException">
    /// The document advertises no <c>jwks_uri</c>. Refused rather than skipped: every SET is signed,
    /// so a transmitter whose keys are unreachable has no verifiable events at all, and letting
    /// resolution fall through to a guessed address answers that with a wrong document instead of a
    /// failure anybody can act on.
    /// </exception>
    public static JwksKeyResolutionOptions AddSharedSignalsJwksUri(
        this JwksKeyResolutionOptions options,
        TransmitterConfiguration transmitter)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(transmitter);

        options.JwksUris[transmitter.Issuer] = transmitter.JwksUri ?? throw new InvalidOperationException(
            $"The transmitter '{transmitter.Issuer}' advertises no "
            + $"'{TransmitterConfiguration.ParameterNames.JwksUri}' in its configuration document, so the "
            + "signature on every event it sends is unverifiable. Serve the key set from that document, or "
            + "name the address explicitly through the key resolution options.");

        return options;
    }
}
