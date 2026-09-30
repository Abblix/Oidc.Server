// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// A tenant this deployment serves.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantDefinition
{
    /// <summary>
    /// The identifier the tenant is registered under.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The tenant's issuer identifier, as it appears in every token the tenant issues and in its discovery
    /// document - and the address the tenant is served at.
    /// </summary>
    /// <remarks>
    /// A request belongs to the tenant whose issuer names its host and the longest start of its path, so the
    /// host and path of the address the discovery document is fetched from are the issuer's, as OpenID Connect
    /// Discovery 1.0 section 4.3 requires: <c>https://acme.example.com</c> serves a whole host,
    /// <c>https://auth.example.com/tenants/acme</c> a path on a shared one. Scheme and port are not compared,
    /// since behind a proxy the request carries its own; the host's forwarded-headers setup decides those.
    /// </remarks>
    public required string Issuer { get; init; }

    /// <summary>
    /// The clients registered with this tenant. A client is known only at the tenant that lists it, or at which it
    /// was registered dynamically, so two tenants may each register a client under the same id.
    /// </summary>
    public IEnumerable<ClientInfo> Clients { get; init; } = [];

    /// <summary>
    /// The scopes this tenant defines beyond the standard ones, as <see cref="OidcOptions.Scopes"/> does for a
    /// server without tenants.
    /// </summary>
    public ScopeDefinition[]? Scopes { get; init; }

    /// <summary>
    /// The resources this tenant issues tokens for, as <see cref="OidcOptions.Resources"/> does for a server
    /// without tenants.
    /// </summary>
    public ResourceDefinition[]? Resources { get; init; }

    /// <summary>
    /// The resource a token is issued for when the request names none, as
    /// <see cref="OidcOptions.DefaultResourceIndicator"/> does for a server without tenants; it must be one of
    /// this tenant's <see cref="Resources"/>.
    /// </summary>
    public Uri? DefaultResourceIndicator { get; init; }

    /// <summary>
    /// The page a user picks an account on, as <see cref="OidcOptions.AccountSelectionUri"/> is for a server
    /// without tenants. A relative address is a page under this tenant's issuer.
    /// </summary>
    public Uri? AccountSelectionUri { get; init; }

    /// <summary>
    /// The page a user gives consent on, as <see cref="OidcOptions.ConsentUri"/> is for a server without tenants.
    /// A relative address is a page under this tenant's issuer.
    /// </summary>
    public Uri? ConsentUri { get; init; }

    /// <summary>
    /// The page a user completes a required interaction on, as <see cref="OidcOptions.InteractionUri"/> is for a
    /// server without tenants. A relative address is a page under this tenant's issuer.
    /// </summary>
    public Uri? InteractionUri { get; init; }

    /// <summary>
    /// The page a user signs in on, as <see cref="OidcOptions.LoginUri"/> is for a server without tenants. A
    /// relative address is a page under this tenant's issuer.
    /// </summary>
    public Uri? LoginUri { get; init; }

    /// <summary>
    /// The page a user creates an account on, as <see cref="OidcOptions.RegistrationUri"/> is for a server without
    /// tenants. A relative address is a page under this tenant's issuer.
    /// </summary>
    public Uri? RegistrationUri { get; init; }

    /// <summary>
    /// The security profile every client of this tenant is held to at the least, as
    /// <see cref="OidcOptions.DefaultSecurityProfile"/> is for a server without tenants.
    /// </summary>
    public ClientSecurityProfile DefaultSecurityProfile { get; init; } = ClientSecurityProfile.None;

    /// <summary>
    /// The key sealing this tenant's pairwise subject identifiers, or null when its clients take public ones only.
    /// Each tenant keeps its own, so the pseudonyms two tenants give one user cannot be matched to each other.
    /// </summary>
    public PairwiseSubjectSettings? PairwiseSubject { get; init; }

    /// <summary>
    /// The keys this tenant signs its tokens with and publishes in its JWKS, as <see cref="OidcOptions.SigningKeys"/>
    /// are for a server without tenants. Each tenant keeps its own, so a party trusting one tenant's keys cannot
    /// verify another tenant's tokens.
    /// </summary>
    public IReadOnlyCollection<JsonWebKey> SigningKeys { get; init; } = [];

    /// <summary>
    /// The keys clients encrypt to this tenant with, as <see cref="OidcOptions.EncryptionKeys"/> are for a server
    /// without tenants. Each tenant keeps its own, so what a client encrypts to one tenant no other can read.
    /// </summary>
    public IReadOnlyCollection<JsonWebKey> EncryptionKeys { get; init; } = [];

    /// <summary>
    /// The custodian's keys this tenant produces with, when the server keeps its keys in a custodian: each tenant
    /// names keys of its own there, as it declares its own <see cref="SigningKeys"/> otherwise.
    /// </summary>
    public CustodianHeldKeys? CustodianKeys { get; init; }
}
