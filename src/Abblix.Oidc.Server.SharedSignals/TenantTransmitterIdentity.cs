// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The transmitter as one tenant: its issuer, and addresses under that issuer.
/// </summary>
/// <remarks>
/// The options name the host without a path, and the paths they name are kept and put under the tenant's issuer,
/// the same way the server serves every endpoint of a tenant under its issuer's path. Each member reads the
/// tenant's definition in force at that moment, so an address minted by a request that began before the tenant moved
/// to another issuer names the issuer it is served at now.
/// </remarks>
/// <param name="current">The tenant's definition in force.</param>
/// <param name="options">The transmitter's options, read for the path of the key set address.</param>
internal sealed class TenantTransmitterIdentity(Func<TenantDefinition> current, SharedSignalsTransmitterOptions options)
    : ITransmitterIdentity
{
    /// <inheritdoc />
    public string Issuer => current().Issuer.OriginalString;

    /// <inheritdoc />
    public Uri? JwksUri => options.JwksUri is { } jwksUri ? Under(jwksUri.PathAndQuery) : null;

    /// <inheritdoc />
    public Uri EndpointsBase => current().Issuer;

    /// <inheritdoc />
    public bool Serves => true;

    /// <inheritdoc />
    /// <remarks>
    /// The tenant's issuer: its receivers are clients of that tenant, and their credentials come from it.
    /// </remarks>
    public string? ReceiverIssuer => Issuer;

    /// <inheritdoc />
    public string? TenantId => current().Id;

    private Uri Under(string pathAndQuery) => new(Issuer.TrimEnd('/') + pathAndQuery, UriKind.Absolute);
}
