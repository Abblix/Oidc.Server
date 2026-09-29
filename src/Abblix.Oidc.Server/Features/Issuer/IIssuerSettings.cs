// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The settings that belong to the issuer serving the request, as opposed to the lengths, lifetimes and limits
/// every issuer of a deployment shares.
/// </summary>
/// <remarks>
/// A deployment serving one issuer takes them from <see cref="OidcOptions"/>; under multi-tenancy each tenant is an
/// issuer and declares its own. A service that builds something from them once keeps it in an
/// <see cref="IIssuerLocal{T}"/>, so that each issuer gets one built from its own settings.
/// </remarks>
public interface IIssuerSettings
{
    /// <summary>
    /// The clients registered with the issuer.
    /// </summary>
    IEnumerable<ClientInfo> Clients { get; }

    /// <summary>
    /// The scopes the issuer defines beyond the standard ones.
    /// </summary>
    ScopeDefinition[]? Scopes { get; }

    /// <summary>
    /// The resources the issuer issues tokens for.
    /// </summary>
    ResourceDefinition[]? Resources { get; }

    /// <summary>
    /// The resource a token is issued for when the request names none.
    /// </summary>
    Uri? DefaultResourceIndicator { get; }

    /// <summary>
    /// The page a user picks an account on.
    /// </summary>
    Uri? AccountSelectionUri { get; }

    /// <summary>
    /// The page a user gives consent on.
    /// </summary>
    Uri? ConsentUri { get; }

    /// <summary>
    /// The page a user completes a required interaction on.
    /// </summary>
    Uri? InteractionUri { get; }

    /// <summary>
    /// The page a user signs in on.
    /// </summary>
    Uri? LoginUri { get; }

    /// <summary>
    /// The page a user creates an account on.
    /// </summary>
    Uri? RegistrationUri { get; }

    /// <summary>
    /// The security profile every client of the issuer is held to at the least.
    /// </summary>
    ClientSecurityProfile DefaultSecurityProfile { get; }
}
