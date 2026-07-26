// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The authorization-request parameters that need a model binder of their own rather than the default string
/// binding: <c>max_age</c>, a count of seconds (OpenID Connect Core 1.0 section 3.1.2.1), and
/// <c>ui_locales</c> / <c>claims_locales</c>, space-separated lists of BCP 47 language tags (sections 3.1.2.1
/// and 5.2).
/// </summary>
/// <remarks>
/// These are driven end to end rather than at the binder, because what can break here is the composition: the
/// generated MVC model declares the marker, the adapter must have a binder registered for it, and the two are
/// wired by a source generator. A unit test on the binder answers none of that - it would pass while the
/// binding silently fell back to the default and left the property null.
/// </remarks>
public class LocalisedAndTimedAuthorizationTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// The parameters bind and the request proceeds. Acceptance is the assertion available here: what the
    /// server does with them afterwards (re-prompting on an aged session, rendering a localised UI) is a
    /// decision this test host does not surface.
    /// </summary>
    [Fact]
    public async Task Authorize_WithMaxAgeAndLocales_BindsAndProceeds()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (_, codeChallenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = codeChallenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.MaxAge] = "3600",
            [AuthorizationRequest.Parameters.UiLocales] = "en-US ru-RU",
            [AuthorizationRequest.Parameters.ClaimsLocales] = "en-US",
        });

        Assert.False(string.IsNullOrEmpty(code));
    }

    /// <summary>
    /// A <c>max_age</c> that is not a number is the caller's protocol error, so the endpoint owes an OAuth
    /// error rather than a server fault. This is also what proves the binder is in the path at all: were it
    /// absent, the value would fail to bind quietly and the request would succeed with no max_age.
    /// </summary>
    [Fact]
    public async Task Authorize_WithAMaxAgeThatIsNotANumber_IsRefusedAsACallerError()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.MaxAge] = "not-a-number",
        });

        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            (int)response.StatusCode < 500,
            $"/authorize answered {(int)response.StatusCode} for a malformed max_age; a value the caller got " +
            "wrong must not surface as a server fault. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A language tag that is not a tag reaches the culture binder, which has to answer rather than throw.
    /// </summary>
    [Fact]
    public async Task Authorize_WithAnUnparsableLocale_IsRefusedAsACallerError()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.UiLocales] = "!!not a tag!!",
        });

        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            (int)response.StatusCode < 500,
            $"/authorize answered {(int)response.StatusCode} for a malformed ui_locales. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
