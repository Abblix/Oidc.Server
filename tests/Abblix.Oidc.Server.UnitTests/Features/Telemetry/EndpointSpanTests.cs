// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

// The tenant a span names comes from the multi-tenancy feature
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// An endpoint's handling runs in a span named after the endpoint, closed with the status its outcome tells and
/// carrying only attributes from their closed sets.
/// </summary>
public sealed class EndpointSpanTests : IDisposable
{
    private const string TestSourceName = "Abblix.Oidc.Server.UnitTests.Telemetry";

    private static readonly ActivitySource TestSource = new(TestSourceName);

    private readonly ConcurrentBag<Activity> _stopped = [];
    private readonly ActivityListener _listener;

    public EndpointSpanTests()
    {
        _listener = new ActivityListener
        {
            // By name: the source asks its listeners while it is being created, before the field holds it
            ShouldListenTo = source => source.Name is OidcTelemetry.SourceName or TestSourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => _stopped.Add(activity),
        };
        ActivitySource.AddActivityListener(_listener);
    }

    public void Dispose() => _listener.Dispose();

    /// <summary>
    /// Runs <paramref name="act"/> under a span of this test, and returns the one endpoint span it started.
    /// </summary>
    private async Task<Activity> SpanOf(Func<Task> act)
    {
        ActivityTraceId trace;
        using (var root = TestSource.StartActivity("test"))
        {
            Assert.NotNull(root);
            trace = root.TraceId;
            await act();
        }

        return Assert.Single(_stopped, span => span.Source.Name == OidcTelemetry.SourceName && span.TraceId == trace);
    }

    private static Task<Result<TokenIssued, OidcError>> Token(Result<TokenIssued, OidcError> result)
        => EndpointSpan.RunAsync(
            TelemetryEndpoints.Token, null, () => Task.FromResult(result), EndpointSpan.ErrorOf);

    private static TokenIssued Issued => new(
        new EncodedJsonWebToken(new JsonWebToken(), "token"),
        TokenTypes.Bearer,
        TimeSpan.FromMinutes(5),
        TokenTypeIdentifiers.AccessToken);

    [Fact]
    public async Task ASuccess_ClosesTheSpanOk()
    {
        var span = await SpanOf(() => Token(Issued));

        Assert.Equal(TelemetryEndpoints.Token, span.OperationName);
        Assert.Equal(TelemetryEndpoints.Token, span.GetTagItem(TelemetryTags.Endpoint));
        Assert.Equal(ActivityStatusCode.Ok, span.Status);
        Assert.Null(span.GetTagItem(TelemetryTags.Error));
    }

    [Fact]
    public async Task ARefusal_ClosesTheSpanWithItsErrorCode()
    {
        var span = await SpanOf(() => Token(new OidcError(ErrorCodes.InvalidGrant, "The code has expired")));

        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal(ErrorCodes.InvalidGrant, span.GetTagItem(TelemetryTags.Error));
        Assert.DoesNotContain(span.Tags, tag => tag.Value == "The code has expired");
    }

    [Fact]
    public async Task AnAuthorizationError_ClosesTheSpanWithItsErrorCode()
    {
        var request = new AuthorizationRequest();
        Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse error = new AuthorizationError(
            request, ErrorCodes.AccessDenied, "The user said no", ResponseModes.Query, null);

        var span = await SpanOf(() => EndpointSpan.RunAsync(
            TelemetryEndpoints.Authorize, null, () => Task.FromResult(error), EndpointSpan.ErrorOf));

        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal(ErrorCodes.AccessDenied, span.GetTagItem(TelemetryTags.Error));
    }

    [Fact]
    public async Task AnException_ClosesTheSpanWithItsTypeAndPassesOn()
    {
        var span = await SpanOf(async () => await Assert.ThrowsAsync<InvalidOperationException>(
            () => EndpointSpan.RunAsync<Result<TokenIssued, OidcError>>(
                TelemetryEndpoints.Token,
                null,
                () => throw new InvalidOperationException("The license terms violation detected"),
                EndpointSpan.ErrorOf)));

        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal(typeof(InvalidOperationException).FullName, span.GetTagItem(TelemetryTags.ErrorType));
    }

    [Fact]
    public async Task UnderMultiTenancy_TheSpanNamesTheTenant()
    {
        var served = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" } };
        var tenants = Mock.Of<ITenantAccessor>(accessor => accessor.Current == served);

        var span = await SpanOf(() => EndpointSpan.RunAsync(
            TelemetryEndpoints.Configuration, tenants, () => Task.FromResult(0), EndpointSpan.NoError));

        Assert.Equal("acme", span.GetTagItem(TelemetryTags.Tenant));
    }

    [Fact]
    public async Task WithoutTenants_TheSpanNamesNone()
    {
        var span = await SpanOf(() => Token(Issued));

        Assert.Null(span.GetTagItem(TelemetryTags.Tenant));
    }

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode, GrantTypes.AuthorizationCode)]
    [InlineData("urn:example:grant-of-the-client", null)]
    public async Task ATokenSpanNamesOnlyAGrantTypeTheServerSupports(string requested, string? named)
    {
        var inner = new Mock<ITokenHandler>();
        inner
            .Setup(h => h.HandleAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Issued);
        var grants = Mock.Of<IAuthorizationGrantHandler>(g => g.GrantTypesSupported == new[] { GrantTypes.AuthorizationCode });
        var traced = new TracedTokenHandler(inner.Object, grants);

        var span = await SpanOf(() => traced.HandleAsync(
            new TokenRequest { GrantType = requested }, new ClientRequest(), CancellationToken.None));

        Assert.Equal(named, span.GetTagItem(TelemetryTags.GrantType));
    }

    [Theory]
    [InlineData(new[] { ResponseTypes.IdToken, ResponseTypes.Code }, "code id_token")]
    [InlineData(new[] { ResponseTypes.Code, "a-value-of-the-client" }, null)]
    [InlineData(new string[0], null)]
    public void AResponseTypeIsNamedOnlyWhenTheProtocolDefinesEachValue(string[] responseType, string? named)
        => Assert.Equal(named, EndpointSpan.ResponseTypeOf(responseType));
}
