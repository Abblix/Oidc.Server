// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A registration or update body the server cannot read as client metadata is refused the same way on both hosts:
/// the JSON error response RFC 7591 section 3.2.2 describes, "an HTTP 400 status code ... with content type
/// "application/json" consisting of a JSON object", carrying invalid_client_metadata and a description that neither
/// repeats the body nor names the server's own types.
/// </summary>
public class ClientMetadataBodyTests(TestFactory factory) : TestBase(factory)
{
    public static TheoryData<string> UnreadableBodies() =>
    [
        $$"""{"{{RegistrationMembers.RedirectUris}}": ["https://client.example/cb\q"]}""",
        $$"""{"{{RegistrationMembers.RedirectUris}}": 5}""",
        "not json",
        string.Empty,
    ];

    [Theory]
    [MemberData(nameof(UnreadableBodies))]
    public async Task AnUnreadableRegistrationBody_IsRefusedAsInvalidClientMetadata(string body)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.RegistrationEndpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, MediaTypeNames.Application.Json),
        };
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertRefusedAsInvalidClientMetadataAsync(response);
    }

    [Theory]
    [MemberData(nameof(UnreadableBodies))]
    public async Task AnUnreadableUpdateBody_IsRefusedAsInvalidClientMetadata(string body)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
        });

        using var request = new HttpRequestMessage(
            HttpMethod.Put, registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>())
        {
            Content = new StringContent(body, Encoding.UTF8, MediaTypeNames.Application.Json),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertRefusedAsInvalidClientMetadataAsync(response);
    }

    /// <summary>
    /// A body of another media type, or of none, is not client metadata the server can read at all, and both hosts
    /// answer it 415 rather than with the metadata refusal.
    /// </summary>
    [Theory]
    [InlineData(MediaTypeNames.Text.Plain)]
    [InlineData(null)]
    public async Task ARegistrationBodyOfAnotherMediaType_IsUnsupported(string? mediaType)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(
            $$"""{"{{RegistrationMembers.RedirectUris}}": ["{{TestConstants.RedirectUri}}"]}"""));
        if (mediaType is not null)
            content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.RegistrationEndpoint) { Content = content };
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    private static async Task AssertRefusedAsInvalidClientMetadataAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        Assert.Equal(MediaTypeNames.Application.Json, response.Content.Headers.ContentType?.MediaType);

        var members = JsonNode.Parse(raw)!.AsObject();
        Assert.Equal(ErrorCodes.InvalidClientMetadata, members[ResponseParameters.Error]!.GetValue<string>());

        var description = members[ResponseParameters.ErrorDescription]!.GetValue<string>();
        Assert.All(description, character => Assert.True(
            RefusalDescriptionTests.IsAllowed(character), $"U+{(int)character:X4} in '{description}'"));
        Assert.DoesNotContain(nameof(System), description, StringComparison.Ordinal);
    }
}
