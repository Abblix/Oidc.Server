// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// A field named after a parameter of the MVC action is unrecognized, and RFC 6749 section 3.2 says of the token
    /// endpoint "The authorization server MUST ignore unrecognized request parameters". The other endpoints are held to
    /// the same in <see cref="ActionParameterNamedFieldTests"/>.
    /// </summary>
    [Theory]
    [InlineData("authenticationRequest")]
    [InlineData("clientRequest")]
    public async Task A_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(string field)
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form),
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            },
            field,
            HttpStatusCode.OK);
    }
}
