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
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

    /// <summary>
    /// Each endpoint handler the container hands out is its decorator: a stub of the host's stands for every handler,
    /// so resolving reaches no further than the decorator and the stub it wraps.
    /// </summary>
    [Fact]
    public void EveryEndpointHandler_IsWrappedInItsSpan()
    {
        var decorators = typeof(TelemetryDecoratorsRegistered).Assembly
            .GetTypes()
            .Where(type => type.Namespace == typeof(TelemetryDecoratorsRegistered).Namespace &&
                           type.Name.StartsWith("Traced", System.StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(15, decorators.Length);

        var services = new ServiceCollection();
        foreach (var handler in decorators.Select(decorator => decorator.GetInterfaces().Single()))
        {
            var stub = (Mock)System.Activator.CreateInstance(typeof(Mock<>).MakeGenericType(handler))!;
            services.AddSingleton(handler, stub.Object);
        }

        services.AddAuthorizationEndpoint();
        services.AddPushedAuthorizationEndpoint();
        services.AddTokenEndpoint();
        services.AddUserInfoEndpoint();
        services.AddEndSessionEndpoint();
        services.AddConfigurationEndpoint();
        services.AddCheckSession();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddBackChannelAuthentication();
        services.AddDeviceAuthorization();
        services.AddDynamicClientRegistration();

        // The token span reads only the grant types supported, so the grants composed above are not built
        services.Replace(ServiceDescriptor.Singleton(Mock.Of<IAuthorizationGrantHandler>()));
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.All(decorators, decorator => Assert.IsType(
            decorator,
            scope.ServiceProvider.GetRequiredService(decorator.GetInterfaces().Single())));
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
