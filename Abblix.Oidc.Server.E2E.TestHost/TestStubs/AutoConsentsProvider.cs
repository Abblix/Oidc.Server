// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test-host consent provider: marks every requested scope / resource as
/// already granted, leaving nothing pending. With <c>Pending</c> empty,
/// <c>AuthorizationRequestProcessor</c> skips the consent prompt and
/// proceeds straight to issuing the authorization code.
/// </summary>
public sealed class AutoConsentsProvider : IUserConsentsProvider
{
    public Task<UserConsents> GetUserConsentsAsync(
        ValidAuthorizationRequest request,
        AuthSession authSession)
    {
        var grantedScopes = (request.Model.Scope ?? [])
            .Select(s => new ScopeDefinition(s))
            .ToArray();
        var grantedResources = (request.Model.Resources ?? [])
            .Select(uri => new ResourceDefinition(uri))
            .ToArray();

        var consents = new UserConsents
        {
            Granted = new ConsentDefinition(grantedScopes, grantedResources),
            Pending = new ConsentDefinition([], []),
        };
        return Task.FromResult(consents);
    }
}
