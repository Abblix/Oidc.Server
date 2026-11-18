// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientManagementTests
{
    /// <summary>
    /// Registering a scope does not widen what the client reaches: a client registered with the scope of a resource
    /// outside the resources the host grants it is refused that resource on every request, whether it names the
    /// resource or the resource is inferred from the scope, and a request naming the granted resource is refused the
    /// scope, which that resource does not declare.
    /// </summary>
    [Theory]
    [InlineData(TestConstants.OtherApiResource, false, ErrorCodes.InvalidTarget)]
    [InlineData(null, true, ErrorCodes.InvalidTarget)]
    [InlineData(TestConstants.ApiResource, false, ErrorCodes.InvalidScope)]
    public async Task A_registered_scope_of_a_resource_outside_the_grant_reaches_no_token_for_it(
        string? resource, bool inferring, string expected)
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<TestTenantSettings>(tenant => tenant.InferResourceFromScope = inferring)));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var scope = $"{Scopes.OpenId} {TestConstants.OtherApiScope}";
        var metadata = NewClientMetadata($"outside-the-grant-{resource}-{inferring}");
        metadata[RequestMembers.Scope] = scope;
        metadata[RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost;
        var registered = await RegisterClientAsync(client, discovery, metadata);

        var (_, challenge) = GeneratePkcePair();
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>(),
            [ClientRequest.Parameters.ClientSecret] = registered[ResponseMembers.ClientSecret]!.GetValue<string>(),
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = metadata[RequestMembers.RedirectUris]![0]!.GetValue<string>(),
            [AuthorizationRequest.Parameters.Scope] = scope,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        if (resource is not null)
            form[AuthorizationRequest.Parameters.Resource] = resource;

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.PushedAuthorizationRequestEndpoint!, form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expected, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }
}
