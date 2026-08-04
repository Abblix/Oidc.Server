// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Guards the DI lifetime contract of the authorization response builders. A host that builds its
/// service provider with scope validation (<c>ValidateScopes</c> / <c>ValidateOnBuild</c> - the
/// ASP.NET Core default in Development and a production best practice) must not hit a captive
/// dependency. Regression for the v2.3 release cycle: <c>EnableImplicitFlow()</c> registered the
/// id-token response builder as a singleton that consumed the scoped identity-token service, so
/// any host with scope validation failed to construct its service provider at startup. The
/// library's own integration tests missed it because they build the provider without validation.
/// </summary>
public class EnableImplicitFlowLifetimeTests
{
    [Fact]
    public void BuildServiceProvider_WithImplicitFlowAndScopeValidation_DoesNotThrow()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        // Host-supplied services the OIDC core depends on (a real ASP.NET host provides these via
        // the MVC layer / its own session service). Stubbed so the graph is complete enough for
        // ValidateOnBuild to focus on lifetime correctness rather than missing host registrations.
        services.AddSingleton(Mock.Of<IParameterValidator>());
        services.AddSingleton(Mock.Of<IRequestInfoProvider>());
        services.AddSingleton(Mock.Of<IAuthSessionService>());
        services.AddHttpContextAccessor();

        // AddOidcCore (not AddOidcServices) so validation targets the OIDC service graph where the
        // captive dependency lived, without the ASP.NET Core MVC controller infrastructure that
        // only a real web host can satisfy under ValidateOnBuild.
        services.AddOidcCore(opts =>
        {
            opts.Issuer = TestConstants.DefaultIssuer.OriginalString;
            opts.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
        });

        services.EnableImplicitFlow();

        // ValidateOnBuild surfaces a captive dependency (a singleton consuming a scoped service)
        // at build time, exactly as a host configured with scope validation would.
        var exception = Record.Exception(() =>
            services.BuildServiceProvider(new ServiceProviderOptions
            {
                ValidateScopes = true,
                ValidateOnBuild = true,
            }));

        Assert.Null(exception);
    }
}
