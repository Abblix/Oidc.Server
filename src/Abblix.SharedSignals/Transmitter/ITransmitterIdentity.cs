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
/// <para>
/// Read once per dispatched event and each time a stream announcement is minted, a stream is created through the
/// management API, the configuration document is served, a bearer challenge is written and the Redis stream store
/// is used, so a deployment answering as more than one issuer - one per tenant of a multi-tenant server - names the
/// issuer serving the request there. The default reads <see cref="SharedSignalsTransmitterOptions"/>.
/// </para>
/// <para>
/// What is fixed at startup still comes from <see cref="SharedSignalsTransmitterOptions"/>: the issuer of streams
/// declared in configuration, the path the configuration document is mapped at, the authority of the poll and
/// management endpoint addresses and the startup warning about a missing key set address.
/// </para>
/// <para>
/// Singletons hold the implementation, so it is registered as a singleton and finds the current request itself,
/// for example through <c>IHttpContextAccessor</c>.
/// </para>
/// </remarks>
public interface ITransmitterIdentity
{
    /// <summary>
    /// The issuer identifier: the "iss" of every security event token and of the configuration metadata (SSF 1.0
    /// Section 7.1). Never empty: an empty one fails the operation that reads it, after whatever that operation has
    /// already written.
    /// </summary>
    string Issuer { get; }

    /// <summary>
    /// Where the keys that verify the transmitter's tokens are published, or null when nothing is advertised.
    /// </summary>
    Uri? JwksUri { get; }
}
