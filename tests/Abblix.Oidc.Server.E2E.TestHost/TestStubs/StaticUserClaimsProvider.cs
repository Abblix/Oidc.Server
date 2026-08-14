// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test-host user-info claims provider: returns a fixed identity
/// (<c>sub = e2e-subject</c>, plus name / email) for every authenticated
/// session. Mirrors the subject set by <see cref="AutoAuthSessionService"/>
/// so id_token / userinfo / access-token claims line up.
/// </summary>
public sealed class StaticUserClaimsProvider : IUserClaimsProvider
{
    public Task<JsonObject?> GetUserClaimsAsync(
        AuthSession authSession,
        ICollection<string> scope,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims,
        ClientInfo clientInfo)
    {
        var claims = new JsonObject
        {
            ["sub"] = authSession.Subject,
            ["name"] = "E2E Test User",
            ["email"] = "e2e@example.com",
        };
        return Task.FromResult<JsonObject?>(claims);
    }
}
