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
/// Read each time it is needed rather than once at startup, so a deployment answering as more than one issuer - one
/// per tenant of a multi-tenant server - names the issuer serving the request. The default reads
/// <see cref="SharedSignalsTransmitterOptions"/>.
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
    /// Section 7.1). Never empty.
    /// </summary>
    string Issuer { get; }

    /// <summary>
    /// Where the keys that verify the transmitter's tokens are published, or null when nothing is advertised.
    /// </summary>
    Uri? JwksUri { get; }

    /// <summary>
    /// The address the transmitter's endpoints are reached under, before the prefix they are mapped with: what the
    /// stream management and poll addresses it publishes start with.
    /// </summary>
    Uri EndpointsBase { get; }

    /// <summary>
    /// Whether a transmitter answers the current request at all. A deployment answering as one issuer per tenant
    /// has none for a request no tenant was resolved for, and its endpoints answer that request 404.
    /// </summary>
    bool Serves { get; }

    /// <summary>
    /// The issuer a receiver's credentials must come from, or null where receivers may come from any.
    /// </summary>
    /// <remarks>
    /// A deployment answering as one issuer per tenant names the tenant's issuer, so the receiver of one tenant
    /// cannot reach another tenant's streams by presenting its own credentials under that tenant's address.
    /// </remarks>
    string? ReceiverIssuer { get; }
}
