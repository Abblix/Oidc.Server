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
public sealed class OptionsTransmitterIdentity(SharedSignalsTransmitterOptions options) : ITransmitterIdentity
{
    /// <inheritdoc />
    public string Issuer => options.Issuer;

    /// <inheritdoc />
    public Uri? JwksUri => options.JwksUri;
}
