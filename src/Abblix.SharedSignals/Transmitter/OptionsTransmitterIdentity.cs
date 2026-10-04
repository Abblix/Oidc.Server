// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The transmitter's identity as its options declare it: one issuer for the whole deployment.
/// </summary>
/// <param name="options">The transmitter's options.</param>
/// <exception cref="ArgumentException">The options name no issuer.</exception>
public sealed class OptionsTransmitterIdentity(SharedSignalsTransmitterOptions options) : ITransmitterIdentity
{
    // Refused when the identity is built, which the dispatcher and the stream management service need before they
    // write anything: found at the first SET instead, a status change or a verification throttle would already be
    // written and the receiver never told.
    private readonly string _issuer = !string.IsNullOrEmpty(options.Issuer)
        ? options.Issuer
        : throw new ArgumentException("A transmitter without an issuer identifier can sign nothing.", nameof(options));

    /// <inheritdoc />
    public string Issuer => _issuer;

    /// <inheritdoc />
    public Uri? JwksUri => options.JwksUri;
}
