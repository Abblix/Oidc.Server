// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test-host consent provider: marks every requested scope / resource as already granted,
/// leaving nothing pending. With <c>Pending</c> empty,
/// <see cref="Abblix.Oidc.Server.Endpoints.Authorization.AuthorizationRequestProcessor"/>
/// skips the consent prompt and proceeds straight to issuing the authorization code.
/// </summary>
/// <remarks>
/// By default this leaves <see cref="ConsentDefinition.AuthorizationDetails"/> as <c>null</c>
/// on <see cref="UserConsents.Granted"/>, which the processor interprets as "legacy provider /
/// passthrough" and emits the post-validator <c>authorization_details</c> from the request
/// (preserving PR #135 byte-exact behaviour the existing E2E tests exercise).
/// <para>
/// Per-test, scenarios opt in to consent-side narrow / deny by sending the
/// <see cref="TestConsentOverrideMiddleware.HeaderName"/> header on their HTTP requests; the
/// middleware stuffs the parsed override into <see cref="HttpContext.Items"/>, and this
/// provider reads it back via <see cref="IHttpContextAccessor"/>. The override travels with
/// each individual request, so there is no static state, no <see cref="AsyncLocal{T}"/> in
/// the test thread (which WebApplicationFactory's TestServer was observed to drop between
/// the test thread and the request handler thread), and no clean-up burden on the test:
/// the override exists exactly for the requests that carry the header.
/// </para>
/// </remarks>
public sealed class AutoConsentsProvider(IHttpContextAccessor httpContextAccessor) : IUserConsentsProvider
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

        var granted = new ConsentDefinition(grantedScopes, grantedResources);

        var items = httpContextAccessor.HttpContext?.Items;
        if (items?[TestConsentOverrideMiddleware.PresenceItemKey] is true)
        {
            granted = granted with
            {
                AuthorizationDetails = items[TestConsentOverrideMiddleware.ValueItemKey] as JsonArray,
            };
        }

        var consents = new UserConsents
        {
            Granted = granted,
            Pending = new ConsentDefinition([], []),
        };
        return Task.FromResult(consents);
    }
}
