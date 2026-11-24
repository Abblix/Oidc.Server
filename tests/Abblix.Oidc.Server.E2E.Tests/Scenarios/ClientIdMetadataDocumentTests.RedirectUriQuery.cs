// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 2.3: the query of a redirect URI "MUST NOT include any parameters
    /// defined for use in the authorization response". A document is held to the rule a registration is, so a client
    /// whose document lists such a redirect URI is an invalid client, refused without a redirect.
    /// </summary>
    [Fact]
    public async Task ADocumentRedirectingToAUriNamingAResponseParameter_IsAnInvalidClient()
    {
        const string redirectUri = "https://client.example.com/cb?code=planted";
        var document = PublicClientDocument();
        document[RegistrationMembers.RedirectUris] = new JsonArray(redirectUri);
        Serve(document);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }
}
