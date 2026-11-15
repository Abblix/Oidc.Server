// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// An unsecured request object (alg "none", RFC 7519 section 6) that carries no client_id claim. RFC 9101 section 5
/// admits only a JWS signed object, so its rule that the two client IDs be identical (section 6.3) does not reach this
/// one; OpenID Connect Core 1.0 section 6.1, which admits it ("The Request Object MAY be signed or unsigned"), has the
/// outer client_id and response_type "match those in the Request Object, if present".
/// </remarks>
public partial class JarRichAuthorizationRequestsTests
{
    /// <summary>
    /// The object carries every parameter but client_id, and the request outside it the client_id alone, or with the
    /// response_type and scope OpenID Connect Core 1.0 section 6.1 has passed outside too. The object names its issuer
    /// or not: section 6.1 asks for iss only "If signed".
    /// </summary>
    [Theory]
    [InlineData("code id_token", null, Arrival.AuthorizeByValue, false, true)]
    [InlineData("code token", null, Arrival.AuthorizeByValue, false, true)]
    [InlineData("code id_token token", null, Arrival.AuthorizeByValue, false, true)]
    [InlineData("code id_token", null, Arrival.AuthorizeByValue, true, true)]
    [InlineData("code", null, Arrival.AuthorizeByValue, false, true)]
    [InlineData("code id_token", ResponseModes.FormPost, Arrival.AuthorizeByValue, false, true)]
    [InlineData("code id_token", null, Arrival.AuthorizeByReference, false, true)]
    [InlineData("code", null, Arrival.AuthorizeByValue, false, false)]
    [InlineData("code id_token", null, Arrival.AuthorizeByReference, false, false)]
    public async Task AnUnsecuredRequestObjectWithoutClientId_IsServedForTheClientIdBesideIt(
        string responseType,
        string? responseMode,
        Arrival arrival,
        bool oauthParametersOutside,
        bool namesIssuer)
    {
        var served = new ServedRequestObject();
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.EnableImplicitFlow();
            services.Replace(ServiceDescriptor.Singleton<ISecureHttpFetcher>(served));
        }));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterUnsecuredObjectClientAsync(client, discovery, responseType);

        var claims = UnsecuredObjectClaims(clientId, discovery.AuthorizationEndpoint, responseType, namesIssuer);
        if (responseMode is not null)
            claims[AuthorizationRequest.Parameters.ResponseMode] = responseMode;

        var parameters = new Dictionary<string, string> { [AuthorizationRequest.Parameters.ClientId] = clientId };
        if (oauthParametersOutside)
        {
            parameters[AuthorizationRequest.Parameters.ResponseType] = responseType;
            parameters[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        }

        Place(served, parameters, arrival, Unsecured(claims));

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
            TestContext.Current.CancellationToken);

        if (responseMode == ResponseModes.FormPost)
        {
            var form = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.True(response.StatusCode == HttpStatusCode.OK, form);
            Assert.Contains(TestConstants.RedirectUri, form);
            return;
        }

        Assert.True(
            response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize returned {(int)response.StatusCode}, expected a redirect to the client: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var location = response.Headers.Location!;
        Assert.Equal(TestConstants.RedirectUri, location.GetLeftPart(UriPartial.Path));
        var callback = System.Web.HttpUtility.ParseQueryString(
            responseType == ResponseTypes.Code ? location.Query : location.Fragment.TrimStart('#'));
        Assert.Null(callback[ResponseParameters.Error]);
        Assert.False(string.IsNullOrEmpty(callback[ResponseParameters.Code]));
    }

    /// <summary>
    /// Where a rule other than OpenID Connect Core 1.0 section 6.1 governs, the object without a client_id claim stays
    /// refused: RFC 9126 section 3 step 3 has a pushed request rejected "if the authenticated "client_id" does not
    /// match the "client_id" claim in the Request Object", and a host processing request objects strictly by RFC 9101
    /// section 6.3 uses "only the parameters in the Request Object".
    /// </summary>
    [Theory]
    [InlineData(Arrival.Pushed, false, true)]
    [InlineData(Arrival.AuthorizeByValue, true, true)]
    [InlineData(Arrival.Pushed, false, false)]
    [InlineData(Arrival.AuthorizeByValue, true, false)]
    public async Task AnUnsecuredRequestObjectWithoutClientId_IsAnInvalidRequestObject_OutsideTheOpenIdConnectRule(
        Arrival arrival,
        bool strict,
        bool namesIssuer)
    {
        await using var host = strict ? CreateStrictHost() : Factory.WithWebHostBuilder(_ => { });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(client, discovery, requireSignedRequestObject: false);

        var parameters = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = poster.ClientId,
            [AuthorizationRequest.Parameters.Request] =
                Unsecured(UnsecuredObjectClaims(poster.ClientId, discovery.Issuer, ResponseTypes.Code, namesIssuer)),
        };

        using var response = await SendAsync(client, discovery, poster, arrival, parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// An unsecured object naming neither its issuer nor a client speaks for the client beside it, and so is held to
    /// what that client committed to: RFC 9101 section 10.5 has a client registered with require_signed_request_object
    /// send only signed objects, and OpenID Connect Dynamic Client Registration 1.0 section 2 has "All Request Objects
    /// from this Client MUST be rejected, if not signed with this algorithm" of request_object_signing_alg.
    /// </summary>
    [Theory]
    [InlineData(true, null)]
    [InlineData(false, SigningAlgorithms.RS256)]
    public async Task AnUnsecuredRequestObjectNamingNoClient_IsAnInvalidRequestObject_ForAClientCommittedToSigning(
        bool requireSignedRequestObject,
        string? requestObjectSigningAlgorithm)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [RegistrationMembers.Jwks] = System.Text.Json.JsonSerializer.SerializeToNode(PublicJwksFor(key)),
            [RegistrationMembers.RequireSignedRequestObject] = requireSignedRequestObject,
            [RegistrationMembers.RequestObjectSigningAlg] = requestObjectSigningAlgorithm,
        });
        var clientId = registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>();

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.Request] = Unsecured(
                    UnsecuredObjectClaims(clientId, discovery.Issuer, ResponseTypes.Code, namesIssuer: false)),
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// The claims of an unsecured request object to <paramref name="audience"/>, issued by <paramref name="clientId"/>
    /// when <paramref name="namesIssuer"/>: every parameter of an OpenID request with PKCE for
    /// <paramref name="responseType"/>, but no client_id.
    /// </summary>
    private static JsonObject UnsecuredObjectClaims(string clientId, Uri audience, string responseType, bool namesIssuer)
    {
        var now = TimeProvider.System.GetUtcNow();
        var claims = new JsonObject
        {
            [JwtClaimTypes.Audience] = audience.OriginalString,
            [JwtClaimTypes.IssuedAt] = now.ToUnixTimeSeconds(),
            [JwtClaimTypes.ExpiresAt] = now.AddMinutes(5).ToUnixTimeSeconds(),
            [JwtClaimTypes.JwtId] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.ResponseType] = responseType,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = GeneratePkcePair().Challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        if (namesIssuer)
            claims[JwtClaimTypes.Issuer] = clientId;

        return claims;
    }

    /// <summary>
    /// An Unsecured JWS (RFC 7515 appendix A.5) over <paramref name="claims"/>: alg "none" and an empty signature.
    /// </summary>
    private static string Unsecured(JsonObject claims)
    {
        var header = new JsonObject
        {
            [JwtClaimTypes.Type] = JsonWebTokenTypes.Jwt,
            [JwtClaimTypes.Algorithm] = SigningAlgorithms.None,
        };
        return string.Join(
            '.',
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString())),
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claims.ToJsonString())),
            string.Empty);
    }

    /// <summary>
    /// Sends <paramref name="requestObject"/> by value in the request parameter, or serves it at the request_uri.
    /// </summary>
    private static void Place(
        ServedRequestObject served,
        Dictionary<string, string> parameters,
        Arrival arrival,
        string requestObject)
    {
        switch (arrival)
        {
            case Arrival.AuthorizeByValue:
                parameters[AuthorizationRequest.Parameters.Request] = requestObject;
                break;

            case Arrival.AuthorizeByReference:
                served.Content = requestObject;
                parameters[AuthorizationRequest.Parameters.RequestUri] = ServedRequestObject.Address;
                break;

            // A pushed object is answered with a request_uri rather than at the client's redirect_uri
            case Arrival.Pushed:
            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }
    }

    /// <summary>
    /// A client of <paramref name="responseType"/> that authenticates with client_secret_basic, is not required to
    /// sign its request objects and may serve them at <see cref="ServedRequestObject.Address"/>.
    /// </summary>
    private static async Task<string> RegisterUnsecuredObjectClientAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string responseType)
    {
        var grantTypes = new JsonArray { GrantTypes.AuthorizationCode };
        if (responseType != ResponseTypes.Code)
            grantTypes.Add(GrantTypes.Implicit);

        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = grantTypes,
            [RegistrationMembers.ResponseTypes] = new JsonArray { responseType },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [RegistrationMembers.RequireSignedRequestObject] = false,
            [RegistrationMembers.RequestUris] = new JsonArray { ServedRequestObject.Address },
        });

        return registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>();
    }
}
