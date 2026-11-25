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
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// The client a request is served for is named on the endpoint's span once a stage authenticated or found it, and
/// only there: never on a stage's span, never on a measurement, and not at all when the stage refused.
/// </summary>
public sealed class ClientOnEndpointSpanTests : IDisposable
{
    private const string ClientId = "client-on-the-span";

    private readonly ConcurrentBag<Activity> _stopped = [];
    private readonly ActivityListener _listener;
    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly MeasurementRecorder _measured;
    private readonly OidcInstruments _instruments;

    public ClientOnEndpointSpanTests()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == OidcTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _stopped.Add,
        };
        ActivitySource.AddActivityListener(_listener);
        var factory = _services.GetRequiredService<IMeterFactory>();
        _measured = new MeasurementRecorder(factory);
        _instruments = new OidcInstruments(new RecordingLoggerFactory(), factory);
    }

    public void Dispose()
    {
        _listener.Dispose();
        _measured.Dispose();
        _services.Dispose();
    }

    /// <summary>
    /// Runs <paramref name="act"/> under a trace of its own, and returns the server's spans of that trace: the source is
    /// shared by every test in the process, so what this test produced is told apart by its trace.
    /// </summary>
    private async Task<Activity[]> SpansOf(Func<Task> act)
    {
        var trace = ActivityTraceId.CreateRandom();
        using (new Activity("test").SetParentId(trace, ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded).Start())
            await act();

        return _stopped.Where(span => span.TraceId == trace).ToArray();
    }

    /// <summary>
    /// Runs <paramref name="stage"/> inside the handling of an endpoint, and returns the endpoint's span and the spans
    /// of its stages.
    /// </summary>
    private async Task<(Activity Endpoint, Activity[] Stages)> UnderAnEndpoint<TResult>(Func<Task<TResult>> stage)
    {
        var spans = await SpansOf(() => EndpointObservation.RunAsync(
            TelemetryEndpoints.Token, _instruments, null, stage, EndpointObservation.NoError));

        var endpoint = Assert.Single(
            spans, span => Equals(span.GetTagItem(TelemetryTags.Endpoint), TelemetryEndpoints.Token));
        return (endpoint, spans.Where(span => span != endpoint).ToArray());
    }

    private static ObservedClientAuthenticator Authenticator(Result<ClientInfo, OidcError> outcome)
    {
        var inner = new Mock<IClientAuthenticator>();
        inner
            .Setup(authenticator => authenticator.TryAuthenticateClientAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(outcome);
        return new ObservedClientAuthenticator(inner.Object);
    }

    private static Task<Result<ClientInfo, OidcError>> Authenticate(ObservedClientAuthenticator authenticator)
        => authenticator.TryAuthenticateClientAsync(
            SingleIssuer.Tenant, new ClientRequest(), Mock.Of<IClientInfoProvider>());

    [Fact]
    public async Task AnAuthenticatedClient_IsNamedOnTheEndpointSpan_AndOnNoStage()
    {
        var (endpoint, stages) = await UnderAnEndpoint(() => Authenticate(Authenticator(new ClientInfo(ClientId))));

        Assert.Equal(ClientId, endpoint.GetTagItem(TelemetryTags.ClientId));
        var stage = Assert.Single(stages);
        Assert.Null(stage.GetTagItem(TelemetryTags.ClientId));
    }

    [Fact]
    public async Task AClientAuthenticationRefused_NamesNoClient()
    {
        var (endpoint, _) = await UnderAnEndpoint(
            () => Authenticate(Authenticator(ClientAuthenticationFailures.NoCredential)));

        Assert.Null(endpoint.GetTagItem(TelemetryTags.ClientId));
    }

    [Fact]
    public async Task AMeasurementOfTheRequest_NamesNoClient()
    {
        await UnderAnEndpoint(() => Authenticate(Authenticator(new ClientInfo(ClientId))));

        Assert.NotEmpty(_measured.Of(OidcMetrics.RequestDuration));
        Assert.DoesNotContain(_measured.AllTags, tag => tag.Key == TelemetryTags.ClientId);
        Assert.DoesNotContain(_measured.AllTags, tag => Equals(tag.Value, ClientId));
    }

    [Fact]
    public async Task AStageOutsideAnEndpoint_NamesTheClientNowhere()
    {
        var spans = await SpansOf(() => Authenticate(Authenticator(new ClientInfo(ClientId))));

        Assert.DoesNotContain(spans, span => span.GetTagItem(TelemetryTags.ClientId) is not null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AnEndSessionRequest_NamesTheClientOnlyWhenItNamesOne(bool namesClient)
    {
        var inner = new Mock<IEndSessionRequestValidator>();
        inner
            .Setup(validator => validator.ValidateAsync(It.IsAny<TenantDefinition>(), It.IsAny<EndSessionRequest>()))
            .ReturnsAsync(new ValidEndSessionRequest(new EndSessionRequest(), namesClient ? new ClientInfo(ClientId) : null));
        var observed = new ObservedEndSessionRequestValidator(inner.Object);

        var (endpoint, _) = await UnderAnEndpoint(() => observed.ValidateAsync(SingleIssuer.Tenant, new EndSessionRequest()));

        Assert.Equal(namesClient ? ClientId : null, endpoint.GetTagItem(TelemetryTags.ClientId));
    }

    [Fact]
    public async Task AUserInfoRequest_NamesTheClientItsTokenWasIssuedTo()
    {
        var inner = new Mock<IUserInfoRequestValidator>();
        inner
            .Setup(validator => validator.ValidateAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<UserInfoRequest>(), It.IsAny<ClientRequest>()))
            .ReturnsAsync(new ValidUserInfoRequest(
                new UserInfoRequest(),
                new AuthSession("subject", "session", DateTimeOffset.UnixEpoch, "idp"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null),
                new ClientInfo(ClientId)));
        var observed = new ObservedUserInfoRequestValidator(inner.Object);

        var (endpoint, stages) = await UnderAnEndpoint(
            () => observed.ValidateAsync(SingleIssuer.Tenant, new UserInfoRequest(), new ClientRequest()));

        Assert.Equal(ClientId, endpoint.GetTagItem(TelemetryTags.ClientId));
        Assert.DoesNotContain(
            stages.Concat([endpoint]).SelectMany(span => span.Tags),
            tag => tag.Value == "subject");
    }

    [Fact]
    public async Task AClientConfigurationRequest_NamesTheClientItsTokenManages()
    {
        var inner = new Mock<IClientRequestValidator>();
        inner
            .Setup(validator => validator.ValidateAsync(It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>()))
            .ReturnsAsync(new ValidClientRequest(new ClientRequest(), new RegisteredClient(new ClientInfo(ClientId), "jti")));
        var observed = new ObservedClientRequestValidator(inner.Object);

        var (endpoint, _) = await UnderAnEndpoint(() => observed.ValidateAsync(SingleIssuer.Tenant, new ClientRequest()));

        Assert.Equal(ClientId, endpoint.GetTagItem(TelemetryTags.ClientId));
    }

    [Fact]
    public async Task ARegistration_NamesTheClientItStored()
    {
        var inner = new Mock<IRegisterClientRequestProcessor>();
        inner
            .Setup(processor => processor.ProcessAsync(It.IsAny<TenantDefinition>(), It.IsAny<ValidClientRegistrationRequest>()))
            .ReturnsAsync(new ClientRegistrationSuccessResponse(ClientId, null, "registration-access-token")
            {
                Metadata = new(),
            });
        var observed = new ObservedRegisterClientRequestProcessor(inner.Object);

        var (endpoint, _) = await UnderAnEndpoint(
            () => observed.ProcessAsync(SingleIssuer.Tenant, null!));

        Assert.Equal(ClientId, endpoint.GetTagItem(TelemetryTags.ClientId));
    }
}
