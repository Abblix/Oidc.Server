// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Who the transmitter is when it is asked: the issuer every security event token it signs names, and where the
/// keys that verify them are published.
/// </summary>
/// <remarks>
/// Read each time it is needed rather than once at startup, so a deployment answering as more than one issuer - one
/// per tenant of a multi-tenant server - names the issuer serving the request. The default reads
/// <see cref="SharedSignalsTransmitterOptions"/>.
/// </remarks>
public interface ITransmitterIdentity
{
    /// <summary>
    /// The issuer identifier: the "iss" of every security event token and of the configuration metadata (SSF 1.0
    /// Section 7.1).
    /// </summary>
    string Issuer { get; }

    /// <summary>
    /// Where the keys that verify the transmitter's tokens are published, or null when nothing is advertised.
    /// </summary>
    Uri? JwksUri { get; }
}
