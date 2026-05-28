// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
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
/// Per-test, scenarios opt in to consent-side narrow / deny via
/// <see cref="OverrideAuthorizationDetails"/>. The override is held in a flat static slot
/// (not <see cref="AsyncLocal{T}"/>): WebApplicationFactory's in-process TestServer was
/// observed to drop ExecutionContext between the test thread and the request-handler thread,
/// leaving AsyncLocal values invisible at the read site. E2E tests run sequentially per
/// <c>[Collection(TestCollection.Name)]</c>, so the static is race-free, and
/// <see cref="OverrideAuthorizationDetails"/> returns <see cref="IDisposable"/> to enforce the
/// reset on scope exit (even on test failure).
/// </para>
/// </remarks>
public sealed class AutoConsentsProvider : IUserConsentsProvider
{
    // Per-test override slot. The state is flat (not AsyncLocal) because
    // WebApplicationFactory's in-process TestServer does not always propagate
    // ExecutionContext into request handlers reliably -- AsyncLocal values set in the
    // test method were observed to be invisible to the singleton's read site. E2E tests
    // run sequentially per [Collection(TestCollection.Name)], so flat static state is
    // race-free here; OverrideAuthorizationDetails returns IDisposable to enforce the
    // reset on scope exit even on test failure.
    private static JsonArray? _grantedAuthorizationDetailsOverride;
    private static bool _hasOverride;

    /// <summary>
    /// Establishes a consent-side <c>authorization_details</c> decision for the duration of
    /// the returned scope. Until disposed, this provider will populate
    /// <see cref="ConsentDefinition.AuthorizationDetails"/> on <see cref="UserConsents.Granted"/>
    /// with <paramref name="grantedAuthorizationDetails"/> instead of leaving it null.
    /// <list type="bullet">
    /// <item><description><c>null</c>: provider explicitly says "no AD opinion" -- pipeline
    /// falls back to the request's value (equivalent to the default unoverridden behaviour).</description></item>
    /// <item><description>Empty <see cref="JsonArray"/>: provider says "user denied every entry"
    /// -- pipeline fails with <c>access_denied</c> when the request carried entries.</description></item>
    /// <item><description>Non-empty: provider says "consented to this narrowed set" -- pipeline
    /// emits this exact value, byte-exact, into the access token.</description></item>
    /// </list>
    /// </summary>
    public static IDisposable OverrideAuthorizationDetails(JsonArray? grantedAuthorizationDetails)
    {
        _grantedAuthorizationDetailsOverride = grantedAuthorizationDetails;
        _hasOverride = true;
        return new Resetter();
    }

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
        if (_hasOverride)
            granted = granted with { AuthorizationDetails = _grantedAuthorizationDetailsOverride };

        var consents = new UserConsents
        {
            Granted = granted,
            Pending = new ConsentDefinition([], []),
        };
        return Task.FromResult(consents);
    }

    private sealed class Resetter : IDisposable
    {
        [SuppressMessage("Major Code Smell", "S2696:Instance members should not write to \"static\" fields",
            Justification = "Intentional: per-test override is held in flat static state because WebApplicationFactory's TestServer does not reliably propagate AsyncLocal across its handler chain. See class-level comment on _grantedAuthorizationDetailsOverride; Resetter's Dispose is the scope-exit half of the IDisposable pattern that releases that state.")]
        public void Dispose()
        {
            _grantedAuthorizationDetailsOverride = null;
            _hasOverride = false;
        }
    }
}
