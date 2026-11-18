// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The services a client's metadata document is fetched and read with, over a document origin the test controls and
/// a clock it moves.
/// </summary>
internal sealed class MetadataDocumentServices : IDisposable
{
    private readonly ServiceProvider _provider;

    public MetadataDocumentServices(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(Clock);
        services.AddSingleton<IMemoryCache>(new TimedMemoryCache(Clock));
        services.AddSingleton<IOptionsMonitor<OidcOptions>>(
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == Options));
        services.AddSingleton<ISecureUriValidator>(new SecureUriValidator(
            Microsoft.Extensions.Options.Options.Create(new SecureHttpFetchOptions()),
            NullLogger<SecureUriValidator>.Instance));
        services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => Origin);

        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.None, ClientAuthenticationMethods.PrivateKeyJwt]);
        services.AddSingleton(authenticator.Object);

        var grants = new Mock<IGrantTypeInformer>();
        grants.Setup(g => g.GrantTypesSupported).Returns([GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]);
        services.AddSingleton(grants.Object);

        var code = new Mock<IAuthorizationResponseBuilder>();
        code.Setup(b => b.ResponseType).Returns(ResponseTypes.Code);
        services.AddSingleton(code.Object);

        services.AddSingleton<ClientIdMetadataDocumentFetcher>();
        services.AddSingleton<HeldMetadataDocuments>();
        configure?.Invoke(services);

        _provider = services.BuildServiceProvider();
    }

    public MetadataDocumentOrigin Origin { get; } = new();

    public FakeTimeProvider Clock { get; } = new(TimeProvider.System.GetUtcNow());

    public OidcOptions Options { get; } = new() { ClientIdMetadataDocuments = { Enabled = true } };

    public IServiceProvider Provider => _provider;

    public T Get<T>() where T : notnull => _provider.GetRequiredService<T>();

    public void Dispose() => _provider.Dispose();
}
