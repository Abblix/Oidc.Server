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

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Locks the startup integrity check for composed singular pipelines: a leaf registered for a composed contract
/// after <c>AddOidcCore</c> shadows the composite on the last-wins singular resolve, silently dropping the built-in
/// pipeline. The check must turn that into a clear startup failure naming the contract.
/// </summary>
public class ComposedPipelineIntegrityServiceTests
{
    private sealed class ShadowingTokenValidator : ITokenContextValidator
    {
        public Task<OidcError?> ValidateAsync(TokenValidationContext context) => Task.FromResult<OidcError?>(null);
    }

    private static ComposedPipelineIntegrityService IntegrityServiceOf(IServiceProvider provider)
        => provider.GetServices<IHostedService>().OfType<ComposedPipelineIntegrityService>().Single();

    [Fact]
    public async Task ShadowingTokenPipelineAfterOidcCore_FailsFast()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(o => o.Issuer = TestConstants.DefaultIssuer.OriginalString);

        // A leaf registered after AddOidcCore composed the family: the singular resolve is last-wins, so this
        // shadows the composite and would silently drop the built-in token-validation pipeline.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenContextValidator, ShadowingTokenValidator>());

        using var provider = services.BuildServiceProvider();
        var integrity = IntegrityServiceOf(provider);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => integrity.StartAsync(default));
        Assert.Contains(nameof(ITokenContextValidator), ex.Message);
    }

    [Fact]
    public async Task IntactComposedPipelines_Validate()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(o => o.Issuer = TestConstants.DefaultIssuer.OriginalString);

        using var provider = services.BuildServiceProvider();
        var integrity = IntegrityServiceOf(provider);

        // No shadowing registration — every composed singular resolves to its composite, so the check passes.
        await integrity.StartAsync(default);
    }
}
