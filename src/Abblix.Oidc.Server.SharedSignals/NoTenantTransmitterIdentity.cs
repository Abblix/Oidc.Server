// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The transmitter for a request no tenant was resolved for: it serves nothing, so its endpoints answer 404.
/// </summary>
/// <remarks>
/// The members other than <see cref="Serves"/> name the transmitter's configured issuer, so a reader asking them
/// before it asks whether anything is served gets an address of this deployment rather than an exception, and still
/// names no tenant.
/// </remarks>
/// <param name="options">The transmitter's options.</param>
internal sealed class NoTenantTransmitterIdentity(SharedSignalsTransmitterOptions options) : ITransmitterIdentity
{
    /// <inheritdoc />
    public string Issuer => options.Issuer;

    /// <inheritdoc />
    public Uri? JwksUri => options.JwksUri;

    /// <inheritdoc />
    public Uri EndpointsBase => new(options.Issuer, UriKind.Absolute);

    /// <inheritdoc />
    public bool Serves => false;

    /// <inheritdoc />
    public string? ReceiverIssuer => null;
}
