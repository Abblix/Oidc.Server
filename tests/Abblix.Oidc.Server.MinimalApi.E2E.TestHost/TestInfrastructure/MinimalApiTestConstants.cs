// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;

/// <summary>
/// Constants specific to the Minimal API test host — those the shared (MVC-linked) <c>TestConstants</c> does not
/// carry. Kept in this assembly so both <c>Program</c> and the test project bind to a single source.
/// </summary>
public static class MinimalApiTestConstants
{
    /// <summary>A registered post-logout redirect URI, so an RP-initiated logout can redirect deterministically
    /// to it and the test can assert the <c>EndSessionRequest</c> bound the <c>post_logout_redirect_uri</c>.</summary>
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test post-logout redirect URI; not a deployment URL.")]
    public const string PostLogoutRedirectUri = "https://client.example.com/logged-out";

    /// <summary>Configuration key the host reads to mount all OIDC endpoints under a route prefix. The routing test
    /// sets it through <c>WebApplicationFactory</c> to verify <c>MapOidcEndpoints(prefix)</c>.</summary>
    public const string RoutePrefixConfigKey = "OidcRoutePrefix";
}
