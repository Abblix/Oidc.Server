// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Unit tests for <see cref="RequestObjectFetchAdapter"/> verifying the OIDC Core section 6.1 rule:
/// response_type and client_id passed in the OAuth request syntax must match the values inside
/// the request object when the object carries them.
/// </summary>
public class RequestObjectFetchAdapterTests
{
    private const string ClientId = "client-1";
    private const string RequestJwt = "header.payload.signature";

    private readonly Mock<IRequestObjectFetcher> _requestObjectFetcher = new(MockBehavior.Strict);
    private readonly ClientInfo _namedClient = new(ClientId);
    private readonly RequestObjectFetchAdapter _adapter;

    public RequestObjectFetchAdapterTests()
    {
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(_namedClient);
        _adapter = new RequestObjectFetchAdapter(_requestObjectFetcher.Object, clients.Object);
    }

    /// <summary>
    /// OpenID Connect Core section 6.1 has the client_id outside the request object too, so the object is fetched for
    /// the client it names, whose profile then bounds every layer of the object before it is read.
    /// </summary>
    [Fact]
    public async Task FetchAsync_HandsTheFetcherTheClientTheRequestNames()
    {
        SetupFetcher(CreateRequest());

        await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest());

        _requestObjectFetcher.Verify(
            f => f.FetchAsync(
                TestTenant.Matched, _namedClient, It.IsAny<AuthorizationRequest>(), RequestJwt,
                It.IsAny<Func<ClientInfo, string?>?>()),
            Times.Once);
    }

    /// <summary>
    /// RFC 9101 section 6.3: "The client ID values in the "client_id" request parameter and in the Request Object
    /// "client_id" claim MUST be identical", and section 4 has the object contain every parameter but "request" and
    /// "request_uri". The object is merged over the request without its client_id, so what comes back names only the
    /// client the object itself names.
    /// </summary>
    [Fact]
    public async Task FetchAsync_MergesTheObjectOverTheRequestWithoutItsClientId()
    {
        SetupFetcher(CreateRequest());

        await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest());

        _requestObjectFetcher.Verify(
            f => f.FetchAsync(
                TestTenant.Matched, _namedClient, It.Is<AuthorizationRequest>(r => r.ClientId == null), RequestJwt,
                It.IsAny<Func<ClientInfo, string?>?>()),
            Times.Once);
    }

    private static AuthorizationRequest CreateRequest(
        string? clientId = ClientId,
        string[]? responseType = null) => new()
    {
        ClientId = clientId,
        ResponseType = responseType ?? [ResponseTypes.Code],
        RedirectUri = new Uri("https://client.example.com/cb"),
        Request = RequestJwt,
    };

    private void SetupFetcher(AuthorizationRequest merged) =>
        _requestObjectFetcher
            .Setup(f => f.FetchAsync(
                TestTenant.Matched, It.IsAny<ClientInfo?>(), It.IsAny<AuthorizationRequest>(), RequestJwt,
                It.IsAny<Func<ClientInfo, string?>?>()))
            .ReturnsAsync(merged);

    /// <summary>
    /// RFC 9101 section 5: "client_id REQUIRED. OAuth 2.0 [RFC6749] "client_id". The value MUST match the "request" or
    /// "request_uri" Request Object's (Section 2.1) "client_id"." A request carrying an object but no client_id beside
    /// it is refused with invalid_request before the object is read, as section 6.3 has a failed client ID check
    /// answered under RFC 6749.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ARequestObjectWithoutAnOuterClientId_IsRefusedUnread()
    {
        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest(clientId: null));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        _requestObjectFetcher.Verify(
            f => f.FetchAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<ClientInfo?>(), It.IsAny<AuthorizationRequest>(),
                It.IsAny<string?>(), It.IsAny<Func<ClientInfo, string?>?>()),
            Times.Never);
    }

    [Fact]
    public async Task FetchAsync_MatchingParameters_ReturnsMergedRequest()
    {
        var outer = CreateRequest();
        SetupFetcher(CreateRequest());

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, outer);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// OIDC Core section 6.1: a request object carrying a different client_id than the OAuth request
    /// syntax must be rejected - otherwise the object could silently swap the client identity.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ClientIdMismatch_ReturnsError()
    {
        var outer = CreateRequest(clientId: ClientId);
        SetupFetcher(CreateRequest(clientId: "another-client"));

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, outer);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// OIDC Core section 6.1: the same matching rule applies to response_type - a request object must not
    /// silently switch the flow relative to what the plain OAuth parameters declared.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ResponseTypeMismatch_ReturnsError()
    {
        var outer = CreateRequest(responseType: [ResponseTypes.Code]);
        SetupFetcher(CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.IdToken]));

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, outer);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// A prompt value the request model does not declare is refused inside a request object as it is in the query.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnsupportedPrompt_ReturnsInvalidRequest()
    {
        SetupFetcher(CreateRequest() with { Prompt = [Prompts.Login, "unknown"] });

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Strict request object processing (RFC 9101 section 6.3) rebuilds the request from the object alone, so the
    /// fetcher returns it without the <c>request</c> parameter that carried the object. The result still names the
    /// object it came from, or a client required to sign its request objects is refused for sending one.
    /// </summary>
    [Fact]
    public async Task FetchAsync_RequestRebuiltFromObjectAlone_KeepsTheRequestObject()
    {
        SetupFetcher(CreateRequest() with { Request = null });

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetSuccess(out var fetched));
        Assert.Equal(RequestJwt, fetched.Request);
    }

    /// <summary>
    /// The object carried on is the one the fetcher validated, never a <c>request</c> member inside its payload.
    /// </summary>
    [Fact]
    public async Task FetchAsync_RequestMemberInsideObject_KeepsTheValidatedObject()
    {
        SetupFetcher(CreateRequest() with { Request = "other.payload.signature" });

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, CreateRequest());

        Assert.True(result.TryGetSuccess(out var fetched));
        Assert.Equal(RequestJwt, fetched.Request);
    }

    /// <summary>
    /// A request read back from storage had its object applied before it was stored, and carries what the server set
    /// since, such as the DPoP key its code is bound to. It passes as stored, the object not applied again.
    /// </summary>
    [Fact]
    public async Task FetchAsync_RequestReadBackFromStorage_PassesAsStored()
    {
        var stored = CreateRequest() with
        {
            PushedRequestUri = new Uri("urn:ietf:params:oauth:request_uri:stored"),
            ProofKeyThumbprint = "stored-thumbprint",
        };

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, stored);

        Assert.True(result.TryGetSuccess(out var fetched));
        Assert.Same(stored, fetched);
        _requestObjectFetcher.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A request object both rebinding the response type and carrying an unsupported prompt is refused for the
    /// rebinding, the graver of the two faults.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ResponseTypeMismatchAndUnsupportedPrompt_ReturnsTheMismatch()
    {
        var outer = CreateRequest(responseType: [ResponseTypes.Code]);
        SetupFetcher(CreateRequest(responseType: [ResponseTypes.IdToken]) with { Prompt = ["unknown"] });

        var result = await _adapter.FetchAsync(SingleIssuer.Tenant, outer);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }
}
