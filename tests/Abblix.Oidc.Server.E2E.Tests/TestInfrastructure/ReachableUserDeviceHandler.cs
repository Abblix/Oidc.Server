// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Test double for the integrator-supplied device interaction. It reports that the user was reached and
/// identifies them, which is what puts the stored request into the Pending state the tests poll against.
/// It never reports the user as having answered, because that is precisely the state under test.
/// </summary>
internal sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
{
    /// <summary>The end-user every request is answered for, whom a client names in its login_hint.</summary>
    public const string Subject = "e2e-subject";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1172",
        Justification = "The parameters belong to the interface; this stand-in answers the same way at every tenant.")]
    public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
        TenantDefinition tenant,
        ValidBackChannelAuthenticationRequest request)
        => Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
            Subject: Subject,
            SessionId: Guid.NewGuid().ToString("N"),
            AuthenticationTime: clock.GetUtcNow(),
            IdentityProvider: "e2e-test"));
}
