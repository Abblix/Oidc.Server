// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// Every endpoint handler a host registers through the library runs in its endpoint's span, and in one span however
/// often its registration method is called.
/// </summary>
public sealed class EndpointSpanRegistrationTests
{
    private const string TestSourceName = "Abblix.Oidc.Server.UnitTests.Telemetry.Registration";

    private static readonly ActivitySource TestSource = new(TestSourceName);

    [Fact]
    public void EveryEndpointHandler_IsWrappedInItsSpan()
    {
        var services = new ServiceCollection();
        services.AddDeviceAuthorization();
        services.AddBackChannelAuthentication();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddCheckSession();
        services.AddDynamicClientRegistration();
        services.AddOidcCore(_ => { });

        var registered = services
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<EndpointSpansRegistered>()
            .Single();

        var decorators = typeof(EndpointSpansRegistered).Assembly
            .GetTypes()
            .Where(type => type.Namespace == typeof(EndpointSpansRegistered).Namespace &&
                           type.Name.StartsWith("Traced", System.StringComparison.Ordinal))
            .ToHashSet();

        Assert.Equal(15, decorators.Count);
        Assert.Equal(decorators.OrderBy(type => type.Name), registered.Decorators.OrderBy(type => type.Name));
    }

    [Fact]
    public async Task ARegistrationMethodCalledTwice_WrapsTheHandlerOnce()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name is OidcTelemetry.SourceName or TestSourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stopped.Add(activity),
        };
        ActivitySource.AddActivityListener(listener);

        var stub = new Mock<IUserInfoHandler>();
        stub.Setup(h => h.HandleAsync(It.IsAny<UserInfoRequest>(), It.IsAny<ClientRequest>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidToken, "Refused"));
        var services = new ServiceCollection();
        services.AddSingleton(stub.Object);
        services.AddUserInfoEndpoint();
        services.AddUserInfoEndpoint();
        await using var provider = services.BuildServiceProvider();

        ActivityTraceId trace;
        using (var root = TestSource.StartActivity("test"))
        {
            Assert.NotNull(root);
            trace = root.TraceId;
            await provider.GetRequiredService<IUserInfoHandler>().HandleAsync(new UserInfoRequest(), new ClientRequest());
        }

        Assert.Single(stopped, span => span.Source.Name == OidcTelemetry.SourceName && span.TraceId == trace);
    }
}
