// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The conformance user's device for the FAPI-CIBA plans: a request naming the user is left pending, and the suite
/// answers it in the user's place through the approval endpoint, approving or denying as the module needs.
/// </summary>
public sealed class ConformanceUserDevice(
    ConformanceUser user,
    ISessionIdGenerator sessionIdGenerator,
    TimeProvider clock) : IUserDeviceAuthenticationHandler
{
    /// <summary>
    /// The identity provider recorded on a session the device authenticates.
    /// </summary>
    private const string DeviceIdentityProvider = "conformance-device";

    public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
        TenantDefinition tenant, ValidBackChannelAuthenticationRequest request)
    {
        if (!user.IsNamedBy(request.Model.LoginHint))
        {
            // CIBA Core 1.0 section 13: "The OpenID Provider is not able to identify which end-user the Client wishes
            // to be authenticated by means of the hint provided in the request"
            return Task.FromResult<Result<AuthSession, OidcError>>(
                new OidcError(ErrorCodes.UnknownUserId, "The hint names no user this host knows"));
        }

        return Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
            ConformanceUser.Subject,
            sessionIdGenerator.GenerateSessionId(),
            clock.GetUtcNow(),
            DeviceIdentityProvider));
    }

    /// <summary>
    /// Records the user's answer to the pending request <paramref name="authReqId"/>: tokens for it once the client
    /// asks, after <c>allow</c>, or <c>access_denied</c>, after <c>deny</c>.
    /// </summary>
    /// <returns>Whether a pending request was found and the action was one of the two.</returns>
    public static async Task<bool> AnswerAsync(
        TenantDefinition tenant,
        string authReqId,
        string action,
        IBackChannelRequestStorage storage,
        IAuthenticationCompletionHandler completion,
        TimeProvider clock)
    {
        if (await storage.TryGetAsync(tenant, authReqId) is not { } pending)
            return false;

        var expiresIn = pending.ExpiresAt - clock.GetUtcNow();
        switch (action)
        {
            case "allow":
                await completion.CompleteAsync(tenant, authReqId, pending, expiresIn);
                return true;

            case "deny":
                await completion.DenyAsync(tenant, authReqId, expiresIn);
                return true;

            default:
                return false;
        }
    }
}
