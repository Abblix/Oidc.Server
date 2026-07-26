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
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Locks the dual-presence invariant of <see cref="ServiceCollectionExtensions.AddAuthorizationGrant{TImpl}"/>:
/// every <see cref="IAuthorizationGrantHandler"/> registered through the helper must also be
/// observable as <see cref="IGrantTypeInformer"/>, so the discovery endpoint and registration-time
/// validators that aggregate <see cref="IGrantTypeInformer"/> see the same set the token endpoint
/// will dispatch on. Silent regression of this invariant is the failure mode this suite catches.
/// </summary>
public class AddAuthorizationGrantTests
{
    /// <summary>
    /// Mirrors <c>ServiceDescriptor.GetImplementationType()</c> (which is internal in
    /// .NET): for factory-based descriptors registered via
    /// <c>ServiceDescriptor.Singleton&lt;TService, TImpl&gt;(factory)</c>, the runtime type
    /// of the factory is <c>Func&lt;IServiceProvider, TImpl&gt;</c> - its second generic
    /// argument is the implementation type the dual-registration helper preserves for
    /// dedup purposes.
    /// </summary>
    private static System.Type? ImplementationTypeOf(ServiceDescriptor d)
    {
        if (d.ImplementationType != null) return d.ImplementationType;
        if (d.ImplementationInstance != null) return d.ImplementationInstance.GetType();
        if (d.ImplementationFactory != null)
        {
            var args = d.ImplementationFactory.GetType().GetGenericArguments();
            if (args.Length == 2) return args[1];
        }
        return null;
    }

    private sealed class StubGrantHandler : IAuthorizationGrantHandler
    {
        public IEnumerable<string> GrantTypesSupported { get; } = ["urn:test:stub"];

        public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
            => Task.FromResult<Result<AuthorizedGrant, OidcError>>(
                new OidcError(ErrorCodes.UnsupportedGrantType, "stub"));
    }

    private sealed class OtherStubGrantHandler : IAuthorizationGrantHandler
    {
        public IEnumerable<string> GrantTypesSupported { get; } = ["urn:test:other"];

        public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
            => Task.FromResult<Result<AuthorizedGrant, OidcError>>(
                new OidcError(ErrorCodes.UnsupportedGrantType, "other"));
    }

    /// <summary>
    /// A single call places the grant handler under both <see cref="IAuthorizationGrantHandler"/>
    /// and <see cref="IGrantTypeInformer"/> service types. This is the core of the invariant -
    /// the rule the helper exists to enforce.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_RegistersUnderBothServiceTypes()
    {
        var services = new ServiceCollection();

        services.AddAuthorizationGrant<StubGrantHandler>();

        var grantHandlerDescriptors = services
            .Where(d => d.ServiceType == typeof(IAuthorizationGrantHandler))
            .ToList();
        var informerDescriptors = services
            .Where(d => d.ServiceType == typeof(IGrantTypeInformer))
            .ToList();

        Assert.Single(grantHandlerDescriptors);
        Assert.Equal(typeof(StubGrantHandler), ImplementationTypeOf(grantHandlerDescriptors[0]));
        Assert.Single(informerDescriptors);
        Assert.Equal(typeof(StubGrantHandler), ImplementationTypeOf(informerDescriptors[0]));
    }

    /// <summary>
    /// The dual-registration shares ONE concrete <typeparamref name="TImpl"/> singleton between
    /// both interface aliases - resolving <see cref="IAuthorizationGrantHandler"/> and
    /// <see cref="IGrantTypeInformer"/> returns the same instance, not two separate ones. This
    /// preserves the «handler is constructed once per host» invariant that the previous direct
    /// dual-registration would have broken.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_BothInterfaceResolutions_ReturnSameInstance()
    {
        var services = new ServiceCollection();
        services.AddAuthorizationGrant<StubGrantHandler>();
        var provider = services.BuildServiceProvider();

        var asGrantHandler = provider.GetRequiredService<IEnumerable<IAuthorizationGrantHandler>>()
            .OfType<StubGrantHandler>()
            .Single();
        var asInformer = provider.GetRequiredService<IEnumerable<IGrantTypeInformer>>()
            .OfType<StubGrantHandler>()
            .Single();
        var asConcrete = provider.GetRequiredService<StubGrantHandler>();

        Assert.Same(asConcrete, asGrantHandler);
        Assert.Same(asConcrete, asInformer);
    }

    /// <summary>
    /// <c>TryAddEnumerable</c> dedupes on <c>(ServiceType, ImplementationType)</c>. Calling the
    /// helper twice with the same impl must not accumulate duplicate entries - repeated
    /// invocations from extension methods that share a handler stay idempotent.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_CalledTwiceWithSameImpl_RegisteredOnce()
    {
        var services = new ServiceCollection();

        services.AddAuthorizationGrant<StubGrantHandler>();
        services.AddAuthorizationGrant<StubGrantHandler>();

        Assert.Single(services, d =>
            d.ServiceType == typeof(IAuthorizationGrantHandler) &&
            ImplementationTypeOf(d) == typeof(StubGrantHandler));
        Assert.Single(services, d =>
            d.ServiceType == typeof(IGrantTypeInformer) &&
            ImplementationTypeOf(d) == typeof(StubGrantHandler));
    }

    /// <summary>
    /// Distinct impl types both register cleanly. Each contributes its own grant types to the
    /// aggregated <c>grant_types_supported</c> set the discovery endpoint advertises and the
    /// registration validator gates against.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_DifferentImpls_RegisteredIndependently()
    {
        var services = new ServiceCollection();

        services.AddAuthorizationGrant<StubGrantHandler>();
        services.AddAuthorizationGrant<OtherStubGrantHandler>();

        var grantHandlerImpls = services
            .Where(d => d.ServiceType == typeof(IAuthorizationGrantHandler))
            .Select(d => ImplementationTypeOf(d))
            .ToList();
        var informerImpls = services
            .Where(d => d.ServiceType == typeof(IGrantTypeInformer))
            .Select(d => ImplementationTypeOf(d))
            .ToList();

        Assert.Contains(typeof(StubGrantHandler), grantHandlerImpls);
        Assert.Contains(typeof(OtherStubGrantHandler), grantHandlerImpls);
        Assert.Contains(typeof(StubGrantHandler), informerImpls);
        Assert.Contains(typeof(OtherStubGrantHandler), informerImpls);
    }

    /// <summary>
    /// <c>AddAuthorizationCodeGrant</c>, the default flow registration, routes through the
    /// helper and dual-registers <see cref="AuthorizationCodeGrantHandler"/>.
    /// </summary>
    [Fact]
    public void AddAuthorizationCodeGrant_RegistersHandlerAsBothServiceTypes()
        => AssertDualRegistered<AuthorizationCodeGrantHandler>(s => s.AddAuthorizationCodeGrant());

    /// <summary>
    /// <c>AddRefreshTokenGrant</c> routes through the helper.
    /// </summary>
    [Fact]
    public void AddRefreshTokenGrant_RegistersHandlerAsBothServiceTypes()
        => AssertDualRegistered<RefreshTokenGrantHandler>(s => s.AddRefreshTokenGrant());

    /// <summary>
    /// <c>AddClientCredentialsGrant</c> routes through the helper.
    /// </summary>
    [Fact]
    public void AddClientCredentialsGrant_RegistersHandlerAsBothServiceTypes()
        => AssertDualRegistered<ClientCredentialsGrantHandler>(s => s.AddClientCredentialsGrant());

    private static void AssertDualRegistered<TImpl>(System.Action<IServiceCollection> register)
        where TImpl : class, IAuthorizationGrantHandler
    {
        var services = new ServiceCollection();
        register(services);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(IAuthorizationGrantHandler) &&
            ImplementationTypeOf(d) == typeof(TImpl));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IGrantTypeInformer) &&
            ImplementationTypeOf(d) == typeof(TImpl));
    }

    /// <summary>
    /// <c>EnablePasswordGrant</c> is the canonical opt-in route hosts use for ROPC.
    /// Verifies it puts <see cref="PasswordGrantHandler"/> in BOTH service-type lists, so a
    /// host that opts in gets the password grant advertised by discovery and accepted by the
    /// registration-time gate without further wiring.
    /// </summary>
    [Fact]
    public void EnablePasswordGrant_RegistersPasswordGrantAsBothServiceTypes()
    {
        var services = new ServiceCollection();

        services.EnablePasswordGrant();

        Assert.Contains(services, d =>
            d.ServiceType == typeof(IAuthorizationGrantHandler) &&
            ImplementationTypeOf(d) == typeof(PasswordGrantHandler));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IGrantTypeInformer) &&
            ImplementationTypeOf(d) == typeof(PasswordGrantHandler));
    }

    /// <summary>
    /// Stock host bootstrap (<c>AddOidcServices</c> is the canonical entry point) registers
    /// every built-in grant handler as <see cref="IGrantTypeInformer"/> via the helper, so the
    /// discovery endpoint and registration-time validators see the same set the token endpoint
    /// dispatches on. <c>Compose&lt;&gt;</c> removes leaves only from
    /// <see cref="IAuthorizationGrantHandler"/> - leaves' <see cref="IGrantTypeInformer"/>
    /// registrations survive composition.
    /// </summary>
    [Fact]
    public void AddOidcServices_RegistersBuiltInGrantHandlersAsGrantTypeInformer()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString);

        var informerImpls = services
            .Where(d => d.ServiceType == typeof(IGrantTypeInformer))
            .Select(d => ImplementationTypeOf(d))
            .ToList();

        Assert.Contains(typeof(AuthorizationCodeGrantHandler), informerImpls);
        Assert.Contains(typeof(RefreshTokenGrantHandler), informerImpls);
        Assert.Contains(typeof(ClientCredentialsGrantHandler), informerImpls);
        Assert.Contains(typeof(JwtBearerGrantHandler), informerImpls);
    }

    /// <summary>
    /// Default <c>AddOidcServices</c> bootstrap does NOT call <c>EnablePasswordGrant()</c>, so
    /// <see cref="PasswordGrantHandler"/> must not appear in the <see cref="IGrantTypeInformer"/>
    /// descriptor list. Catches a regression where a future change registers
    /// <see cref="PasswordGrantHandler"/> unconditionally.
    /// </summary>
    [Fact]
    public void AddOidcServices_WithoutPasswordOptIn_ExcludesPasswordGrantFromInformer()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString);

        var informerImpls = services
            .Where(d => d.ServiceType == typeof(IGrantTypeInformer))
            .Select(d => ImplementationTypeOf(d))
            .ToList();

        Assert.DoesNotContain(typeof(PasswordGrantHandler), informerImpls);
    }

    /// <summary>
    /// When the host opts into ROPC via <c>EnablePasswordGrant()</c> BEFORE <c>AddOidcServices</c>,
    /// <see cref="PasswordGrantHandler"/> appears in the <see cref="IGrantTypeInformer"/> descriptor list - proving
    /// the opt-in surfaces in the same registry discovery and the registration validator read. The opt-in must
    /// precede <c>AddOidcCore</c> so the handler is included in the composite the token endpoint dispatches on;
    /// registering it after is rejected by the ordering guard (see below).
    /// </summary>
    [Fact]
    public void AddOidcServices_WithPasswordOptIn_IncludesPasswordGrantInInformer()
    {
        var services = new ServiceCollection();
        services
            .EnablePasswordGrant()
            .AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString);

        var informerImpls = services
            .Where(d => d.ServiceType == typeof(IGrantTypeInformer))
            .Select(d => ImplementationTypeOf(d))
            .ToList();

        Assert.Contains(typeof(PasswordGrantHandler), informerImpls);
    }

    /// <summary>
    /// A grant handler registered AFTER the grant handlers were composed by <c>AddOidcCore</c> would land beside the
    /// composite rather than inside it, so the token endpoint would silently not dispatch its grant type. The
    /// ordering guard turns that latent misconfiguration into a loud startup error naming the offending handler and
    /// pointing at the fix - call the opt-in before <c>AddOidcCore</c>.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_AfterOidcCore_ThrowsWithOrderingGuidance()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString);

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.AddAuthorizationGrant<StubGrantHandler>());

        Assert.Contains(nameof(StubGrantHandler), exception.Message);
        Assert.Contains("AddOidcCore", exception.Message);
    }

    /// <summary>
    /// The mirror of the guard: a grant handler registered BEFORE <c>AddOidcCore</c> - the correct order - is
    /// accepted, and the subsequent composition does not throw. This is the path every opt-in feature method takes.
    /// </summary>
    [Fact]
    public void AddAuthorizationGrant_BeforeOidcCore_IsAccepted()
    {
        var services = new ServiceCollection();
        services.AddAuthorizationGrant<StubGrantHandler>();

        var exception = Record.Exception(
            () => services.AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString));

        Assert.Null(exception);
    }

    /// <summary>
    /// The guard fires through a real opt-in feature method, not only the low-level helper: calling
    /// <c>EnablePasswordGrant()</c> after <c>AddOidcServices</c> - the exact misuse a host might commit - is rejected
    /// with the grant handler named and the fix pointed at. This is the consumer-facing shape of the ordering
    /// contract, and the regression that would return if the sentinel check were removed.
    /// </summary>
    [Fact]
    public void EnablePasswordGrant_AfterOidcCore_IsRejectedByTheOrderingGuard()
    {
        var services = new ServiceCollection();
        services.AddOidcServices(opts => opts.Issuer = TestConstants.DefaultIssuer.OriginalString);

        var exception = Assert.Throws<InvalidOperationException>(() => services.EnablePasswordGrant());

        Assert.Contains(nameof(PasswordGrantHandler), exception.Message);
        Assert.Contains("AddOidcCore", exception.Message);
    }
}
