// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Refuses a client whose registration cannot satisfy the security profile it is held to, at the
/// moment it authenticates.
/// </summary>
/// <remarks>
/// The same requirements are checked where a client is configured - at dynamic registration and
/// over <see cref="Features.MultiTenancy.TenantDefinition.Clients"/> at startup - and that covers every client the deployment
/// declares. It does not cover a client that was registered dynamically while no profile was in
/// force and is still in the store: turning the profile on afterwards leaves it
/// authenticating with whatever it registered with, because nothing re-reads a stored registration.
///
/// So the profile is enforced here as well, where every client arrives whatever its origin. The
/// checker is the one the configuration paths use, rather than a second reading of the same
/// requirements that could drift from it.
///
/// A refusal is a null result, indistinguishable to the caller from a credential that did not
/// verify. That is deliberate: which of the two it was tells an unauthenticated caller something
/// about a client registration, and every endpoint here already answers an unauthenticated client
/// the same way.
/// </remarks>
internal partial class SecurityProfileClientAuthenticator(
    IClientAuthenticator inner,
    ILogger<SecurityProfileClientAuthenticator> logger) : IClientAuthenticator
{
    public IEnumerable<string> ClientAuthenticationMethodsSupported
        => inner.ClientAuthenticationMethodsSupported;

    public async Task<ClientInfo?> TryAuthenticateClientAsync(TenantDefinition tenant, ClientRequest request)
    {
        var clientInfo = await inner.TryAuthenticateClientAsync(tenant, request);
        if (clientInfo == null)
            return null;

        // The raw value, because the question below is whether this server DEFINES it - not what
        // it demands. What the client is held to comes from the combination further down, which
        // takes the tenant's demands as a floor; this read must not, or an undefined value the
        // client set would be hidden behind a defined default of the tenant.
        var profile = SecurityProfileRequirements.ProfileNamedFor(tenant, clientInfo);

        // Said where a client is met after proving who it is. The value cannot be interpreted, so
        // the client is held to every control this server can demand - and without this line the
        // operator sees only the consequence: refusals citing requirements no configuration of
        // theirs sets. It does not refuse; whether such a client can work is answered by the
        // requirements below, like any other.
        //
        // It covers the endpoints that authenticate a client and no others. The authorization
        // endpoint reads the same stored client by id and could say the same thing, but nothing
        // there presents a credential, so a client whose only traffic is /authorize is named
        // nowhere today.
        if (!Enum.IsDefined(profile))
        {
            LogProfileIsNotOneThisServerDefines(clientInfo.ClientId, (int)profile);
        }

        var requirements = SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile);

        // FAPI 1.0 Part 1 section 5.2.2: invalid_client "when mis-matched client identifiers were provided through the
        // client authentication methods that permits sending the client identifier in more than one way". The
        // credential decided which client this is, so a client_id naming another one is refused rather than ignored
        if (requirements.RequireMatchingClientIdentifiers &&
            request.ClientId is { Length: > 0 } namedClientId &&
            !string.Equals(namedClientId, clientInfo.ClientId, StringComparison.Ordinal))
        {
            LogClientIdentifiersMismatch(clientInfo.ClientId, Sanitized.Value(namedClientId));
            return null;
        }
        IReadOnlyList<string> violations =
        [
            ..SecurityProfileConsistency.FindViolations(
                clientInfo.EffectiveResponseTypes,
                clientInfo.TokenEndpointAuthMethod,
                clientInfo.ClientAssertionAudiences,
                requirements),
            ..SecurityProfileConsistency.FindAlgorithmViolations(clientInfo, requirements),
            ..SecurityProfileConsistency.FindJwksUriViolations(clientInfo.JwksUri, requirements),
        ];

        if (violations.Count == 0)
            return clientInfo;

        // Two wordings rather than one with an absent value in it: the generator renders a null as
        // "(null)", which names the shape of a field where the sentence is about a client, and a
        // sentinel string would put prose where a consumer expects a value it can query.
        if (clientInfo.SecurityProfile is { } named)
            LogRegistrationCannotSatisfyProfile(
                clientInfo.ClientId, named, tenant.DefaultSecurityProfile, violations);
        else
            LogRegistrationCannotSatisfyDeploymentProfile(
                clientInfo.ClientId, tenant.DefaultSecurityProfile, violations);
        return null;
    }
}
