// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Pins that <see cref="PushModeValidator"/> participates in the CIBA backchannel
/// authentication validation pipeline that <c>AddOidcServices</c> wires up. Without the
/// registration the validator is dead code and push-mode requests are never checked for
/// the mandatory notification endpoint at request time. The pipeline is resolved through
/// DI and the composed validator set is inspected directly, so the test reflects the real
/// pipeline a host runs (the individual validators are captured inside the composite by
/// <c>Compose()</c>, not left as service descriptors). <see cref="PingModeValidator"/> is
/// asserted alongside as a methodology anchor - it is registered, so the test distinguishes
/// "validator missing" from "inspection technique broken".
/// </summary>
public class PushModeValidatorRegistrationTests
{
    [Fact]
    public void AddOidcServices_WiresBothPingAndPushModeValidatorsIntoTheBackChannelPipeline()
    {
        var provider = BuildProvider();

        var composite = provider.GetRequiredService<IBackChannelAuthenticationContextValidator>();
        var validators = ExtractComposedValidators(composite);

        Assert.Contains(validators, v => v is PingModeValidator);
        Assert.Contains(validators, v => v is PushModeValidator);
    }

    private static IBackChannelAuthenticationContextValidator[] ExtractComposedValidators(
        IBackChannelAuthenticationContextValidator composite)
    {
        // Compose() removes the individual IBackChannelAuthenticationContextValidator
        // descriptors and captures them inside the composite's constructor-injected array,
        // so the only way to observe the real pipeline is to read that array back. Locate it
        // by field type rather than by the compiler-generated capture-field name.
        var field = composite.GetType()
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .Single(f => f.FieldType == typeof(IBackChannelAuthenticationContextValidator[]));

        return (IBackChannelAuthenticationContextValidator[])field.GetValue(composite)!;
    }

    private static IServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();

        // Host-level prerequisites every real ASP.NET host registers (the DI analog of
        // AddLogging): memory-backed caches for Storages, and stubbed host-supplied services
        // the CIBA validator pipeline transitively touches.
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        // CIBA is opt-in (off in the OidcEndpoints.Base set) and carries a grant handler, so it must be
        // registered before AddOidcServices composes the grant handlers. This test inspects its validator pipeline.
        services.AddBackChannelAuthentication();

        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
            options.RequireInitialAccessToken = false;
        });

        return services.BuildServiceProvider();
    }
}
