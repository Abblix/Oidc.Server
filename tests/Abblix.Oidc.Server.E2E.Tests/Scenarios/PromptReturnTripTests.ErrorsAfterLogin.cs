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
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// RFC 9700 section 4.11.2: "The authorization server MUST always authenticate the user first and, with the exception
/// of the silent authentication use case, prompt the user for credentials when needed, before redirecting the user."
/// An erroneous request, here one naming a code challenge method the server does not support, reaches its error only
/// once the end user has logged in, where the error is going to be redirected.
/// </remarks>
public partial class PromptReturnTripTests
{
    /// <summary>
    /// A code challenge method the server cannot apply, refused with invalid_request (RFC 7636 section 4.4.1).
    /// </summary>
    private const string UnsupportedChallengeMethod = "S384";

    /// <summary>
    /// The ways of sending a request whose error is found at the authorization endpoint: a pushed request is refused
    /// at the pushed authorization request endpoint already.
    /// </summary>
    public static TheoryData<RequestTransport> TransportsRefusedAtTheAuthorizationEndpoint()
        => [RequestTransport.Query, RequestTransport.RequestObject];

    /// <summary>
    /// With nobody signed in, the erroneous request goes to the login page; after the end user logs in and the page
    /// sends the request back, the same error reaches the client at its redirect URI, with its state.
    /// </summary>
    [Theory]
    [MemberData(nameof(TransportsRefusedAtTheAuthorizationEndpoint))]
    public async Task AnError_WithNobodySignedIn_ReachesTheClientAfterTheLogin(RequestTransport transport)
    {
        var (client, endUser, host) = StartErroneous(trustEveryClient: true);
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);

        var (clientId, sentTo) = await SendErroneousAsync(client, discovery, transport, prompt: null);
        Assert.Equal(LoginPath, PathOf(sentTo));

        endUser.SignInAgain();
        var location = await ReturnFromPage(client, discovery, clientId, sentTo);

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
        Assert.Equal(State, QueryValue(location, ResponseParameters.State));
    }

    /// <summary>
    /// The error of a client whose redirect URIs are not trusted is not going to be redirected, so it owes no login: the
    /// server answers it with status 400 at once, with nobody signed in.
    /// </summary>
    [Fact]
    public async Task AnErrorOfAnUntrustedClient_WithNobodySignedIn_IsAnsweredByTheServerAtOnce()
    {
        var (client, endUser, host) = StartErroneous(trustEveryClient: false);
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(
            client,
            discovery,
            prompt: null,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = UnsupportedChallengeMethod,
            });

        using var response = await client.GetAsync(
            await FirstLegAsync(client, discovery, clientId, clientSecret, requestObject, pushed: false),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {body}");
        Assert.Null(response.Headers.Location);
        Assert.Equal(ErrorCodes.InvalidRequest, JsonNode.Parse(body)![ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A registration removed after the request found its client, while registration is open, leaves a client nobody
    /// answers for: its error is answered by the server with status 400, with the end user signed in, rather than
    /// redirected to the client because it is no longer found among the registrations.
    /// </summary>
    [Fact]
    public async Task AnErrorOfAClientWhoseRegistrationIsRemoved_IsAnsweredByTheServer()
    {
        var endUser = new SignedInEndUser();
        using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(endUser));
            services.Replace(ServiceDescriptor.Singleton<IRedirectUriTrustPolicy, RedirectUriTrustPolicy>());
            services.Decorate<IAuthorizationRequestValidator, RegistrationRemovingValidator>();
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(
            client,
            discovery,
            prompt: null,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = UnsupportedChallengeMethod,
            });

        using var response = await client.GetAsync(
            await FirstLegAsync(client, discovery, clientId, clientSecret, requestObject, pushed: false),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {body}");
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// Removes the registration of the client a request names once the request is validated, as its registrant
    /// deleting it (RFC 7592 section 2.3) while the request is answered does.
    /// </summary>
    private sealed class RegistrationRemovingValidator(IAuthorizationRequestValidator inner, IClientInfoManager registrations)
        : IAuthorizationRequestValidator
    {
        public async Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(
            TenantDefinition tenant,
            AuthorizationRequest request,
            IClientInfoProvider clients)
        {
            var result = await inner.ValidateAsync(tenant, request, clients);
            if (request.ClientId is { } clientId &&
                await registrations.TryFindRegisteredClientAsync(tenant, clientId) is { } registered)
            {
                await registrations.TryRemoveClientAsync(tenant, registered);
            }

            return result;
        }
    }

    /// <summary>
    /// A silent request cannot show the login page, so its error reaches the client at once, with nobody signed in.
    /// </summary>
    [Theory]
    [MemberData(nameof(TransportsRefusedAtTheAuthorizationEndpoint))]
    public async Task ASilentRequestsError_WithNobodySignedIn_ReachesTheClientAtOnce(RequestTransport transport)
    {
        var (client, endUser, host) = StartErroneous(trustEveryClient: true);
        using var _ = host;
        endUser.HasSession = false;
        var discovery = await FetchDiscoveryAsync(client);

        var (_, location) = await SendErroneousAsync(client, discovery, transport, Prompts.None);

        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Equal(ErrorCodes.InvalidRequest, QueryValue(location, ResponseParameters.Error));
    }

    /// <summary>
    /// The server over an end user the test signs in, with the clients it
    /// registers trusted or left to the server's own policy.
    /// </summary>
    private (HttpClient Client, SignedInEndUser EndUser, IDisposable Host) StartErroneous(bool trustEveryClient)
    {
        var endUser = new SignedInEndUser();
        var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(endUser));
            if (!trustEveryClient)
                services.Replace(ServiceDescriptor.Singleton<IRedirectUriTrustPolicy, RedirectUriTrustPolicy>());
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return (client, endUser, host);
    }

    /// <summary>
    /// Sends a request naming <see cref="UnsupportedChallengeMethod"/> the way <paramref name="transport"/> names, and
    /// returns the client it was sent for and where the authorization endpoint sent the browser.
    /// </summary>
    private static async Task<(string ClientId, Uri SentTo)> SendErroneousAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        RequestTransport transport,
        string? prompt)
    {
        switch (transport)
        {
            case RequestTransport.Query:
            {
                var parameters = AuthorizeParameters(prompt ?? Prompts.Login);
                parameters[AuthorizationRequest.Parameters.CodeChallengeMethod] = UnsupportedChallengeMethod;
                if (prompt is null)
                    parameters.Remove(AuthorizationRequest.Parameters.Prompt);

                return (TestConstants.ConfidentialClientId, await RedirectOf(
                    client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters)));
            }

            case RequestTransport.RequestObject:
            {
                var (clientId, clientSecret, requestObject) = await SignedRequestAsync(
                    client,
                    discovery,
                    prompt,
                    new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.CodeChallengeMethod] = UnsupportedChallengeMethod,
                    });
                return (clientId, await RedirectOf(client, await FirstLegAsync(
                    client, discovery, clientId, clientSecret, requestObject, pushed: false)));
            }

            case RequestTransport.Pushed:
            case RequestTransport.PushedRequestObject:
            default:
                throw new ArgumentOutOfRangeException(nameof(transport), transport, null);
        }
    }
}
