// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end guard for the OAuth-shaped rendering of model-layer validation failures on the OIDC
/// endpoints. A value that breaks a declarative <c>[AllowedValues]</c> constraint (here <c>prompt</c>) is
/// rejected by <c>[ApiController]</c> model validation before the handler runs. The response must be the
/// OAuth error envelope <c>{ "error": "invalid_request", ... }</c> served as <c>application/json</c>, not
/// the framework-default <c>ValidationProblemDetails</c> (<c>application/problem+json</c>) that omits the
/// <c>error</c> code OAuth/OIDC clients read. Without the <c>[ReturnsOidcInvalidRequest]</c> attribute on the
/// controller this test fails: the problem+json body carries no <c>error</c> key and the wrong media type.
/// </summary>
public class ModelValidationResponseTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Authorize_WithInvalidPromptValue_ReturnsOAuthInvalidRequestJson()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (_, challenge) = GeneratePkcePair();
        var authorizeUri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,

            // Not one of the spec-fixed prompt values, so the generated model's [AllowedValues] rejects it
            // at the model-binding layer, before redirect_uri is validated — hence a direct response, not a
            // redirect with an error.
            [AuthorizationRequest.Parameters.Prompt] = "bogus",
        });

        var response = await client.GetAsync(authorizeUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The decisive check: OAuth JSON, not the [ApiController] default ValidationProblemDetails, whose
        // media type is application/problem+json and whose body carries no OAuth error code.
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var body = JsonNode.Parse(raw)!.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, body["error"]!.GetValue<string>());
        Assert.False(string.IsNullOrWhiteSpace(body["error_description"]?.GetValue<string>()));
    }
}
