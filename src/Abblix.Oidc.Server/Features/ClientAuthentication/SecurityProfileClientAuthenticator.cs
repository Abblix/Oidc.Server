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
/// over <see cref="OidcOptions.Clients"/> at startup - and that covers every client the deployment
/// declares. It does not cover a client that was registered dynamically while no profile was in
/// force and has been in the store ever since: turning the profile on afterwards leaves it
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
    IOptions<OidcOptions> options,
    ILogger<SecurityProfileClientAuthenticator> logger) : IClientAuthenticator
{
    public IEnumerable<string> ClientAuthenticationMethodsSupported
        => inner.ClientAuthenticationMethodsSupported;

    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        var clientInfo = await inner.TryAuthenticateClientAsync(request);
        if (clientInfo == null)
            return null;

        var profile = clientInfo.SecurityProfile ?? options.Value.DefaultSecurityProfile;

        // A client arrives from a store the HOST writes, so its profile is not covered by the
        // startup check over the configured clients: a value outside the enum reaches here, and
        // resolving one throws. Refusing it is the answer rather than letting the exception out,
        // because the alternative is a 500 from the token endpoint - the failure this whole class
        // exists to remove - for a client the server simply cannot decide about.
        if (!Enum.IsDefined(profile))
        {
            LogProfileIsNotOneThisServerDefines(clientInfo.ClientId, (int)profile);
            return null;
        }

        var violations = SecurityProfileConsistency.FindViolations(
            clientInfo.EffectiveResponseTypes,
            clientInfo.TokenEndpointAuthMethod,
            profile);

        if (violations.Count == 0)
            return clientInfo;

        LogRegistrationCannotSatisfyProfile(clientInfo.ClientId, profile, violations);
        return null;
    }

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.RegistrationCannotSatisfyProfile,
        Level = LogLevel.Warning,
        Message = "The client {ClientId} authenticated, but its registration cannot satisfy the "
                  + "{Profile} profile it is held to: {@Violations}")]
    private partial void LogRegistrationCannotSatisfyProfile(
        string ClientId,
        ClientSecurityProfile Profile,
        IReadOnlyList<string> Violations);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.SecurityProfileClientAuthenticator.ProfileIsNotOneThisServerDefines,
        Level = LogLevel.Error,
        Message = "The client {ClientId} is held to security profile {Profile}, which this server "
                  + "does not define, so nothing can decide what it requires")]
    private partial void LogProfileIsNotOneThisServerDefines(string ClientId, int Profile);
}
