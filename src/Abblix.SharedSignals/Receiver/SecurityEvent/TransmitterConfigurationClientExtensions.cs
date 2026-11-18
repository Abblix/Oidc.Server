// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// Fetches a transmitter's configuration metadata from the address its issuer identifier resolves to.
/// </summary>
public static class TransmitterConfigurationClientExtensions
{
    /// <summary>
    /// Fetches the Transmitter Configuration Metadata for <paramref name="issuer"/> from the well-known address the
    /// issuer identifier resolves to (SSF 1.0 Sections 7.2, 7.2.1), the conformant location.
    /// </summary>
    /// <param name="client">The client the document is fetched with.</param>
    /// <param name="issuer">The transmitter's issuer identifier, from a trusted source
    /// (SSF 1.0 Section 7.2).</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>The metadata document, its issuer identity confirmed.</returns>
    /// <exception cref="HttpRequestException">The transmitter answered with an error status.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The document is empty, or asserts an issuer other than the one it was fetched for - the
    /// SSF counterpart of the identity check every discovery protocol makes, without which a
    /// document served on one issuer's path could impersonate another issuer of the same host.
    /// </exception>
    public static Task<TransmitterConfiguration> GetAsync(
        this TransmitterConfigurationClient client,
        Uri issuer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return client.GetAsync(issuer, TransmitterConfiguration.WellKnownAddress(issuer), cancellationToken);
    }
}
