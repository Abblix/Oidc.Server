// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// Teaches key resolution where one transmitter's signing keys are, from the transmitter's own
/// configuration document.
/// </summary>
public static class TransmitterKeyResolution
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
    public static JwksKeyResolutionOptions AddTransmitterKeys(
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
