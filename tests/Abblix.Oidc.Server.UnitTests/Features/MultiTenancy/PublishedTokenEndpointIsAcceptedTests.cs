// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The token endpoint discovery publishes and the one the JWT bearer grant accepts as an assertion's audience are the
/// same value, both taken from <see cref="TenantEndpointAddresses"/>: with the transport resolving the endpoint on a
/// host and port of the request's, the document publishes the owner's address, and the grant accepts exactly that
/// address and refuses the request's spelling.
/// </summary>
public class PublishedTokenEndpointIsAcceptedTests
{
    private static readonly Uri ResolvedOnTheRequestsHost = new("https://request-host.example.com:8443/connect/token");

    [Fact]
    public async Task ThePublishedTokenEndpoint_IsTheGrantsCanonicalSpelling()
    {
        var tenant = SingleIssuer.Tenant;
        var resolver = new Mock<IOidcEndpointResolver>();
        resolver.Setup(r => r.Resolve(OidcEndpoints.Token)).Returns(ResolvedOnTheRequestsHost);

        var published = await PublishedTokenEndpointAsync(resolver.Object);
        var validateAudience = AudienceCheck(resolver.Object, tenant);

        Assert.Equal(tenant.Published(ResolvedOnTheRequestsHost), published);
        Assert.Equal(published.OriginalString, tenant.AcceptedSpellings(ResolvedOnTheRequestsHost)[0]);
        Assert.True(await validateAudience([published.OriginalString]));
        Assert.False(await validateAudience([ResolvedOnTheRequestsHost.OriginalString]));
    }

    /// <summary>
    /// The token_endpoint member of the discovery document the MVC transport formats over <paramref name="resolver"/>.
    /// </summary>
    private static async Task<Uri> PublishedTokenEndpointAsync(IOidcEndpointResolver resolver)
    {
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions
        {
            Discovery = new DiscoveryOptions { AllowEndpointPathsDiscovery = true },
            EnabledEndpoints = OidcEndpoints.Token,
        });
        var formatter = new ConfigurationResponseFormatter(
            options.Object,
            resolver,
            new SignedMetadataProvider(
                new ProfiledJwtIssuer(new Mock<IJsonWebTokenCreator>(MockBehavior.Strict).Object, TestEncryptionAlgorithms.Every),
                new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict).Object,
                new FakeTimeProvider(),
                TestSigningAlgorithms.Registered),
            SingleIssuer.Accessor);

        var result = Assert.IsType<ObjectResult>(await formatter.FormatResponseAsync(new EndpointResponse
        {
            Issuer = SingleIssuer.Tenant.Issuer,
            ResponseTypesSupported = [ResponseTypes.Code],
            IdTokenSigningAlgValuesSupported = [SigningAlgorithms.RS256],
            SubjectTypesSupported = [SubjectTypes.Public],
        }));
        var document = Assert.IsType<ModelResponse>(result.Value);
        return Assert.IsType<Uri>(document.TokenEndpoint);
    }

    /// <summary>
    /// The audience check the JWT bearer grant validates an assertion presented at <paramref name="tenant"/> with,
    /// over a transport resolving the token endpoint through <paramref name="resolver"/>.
    /// </summary>
    private static ValidationParameters.ValidateAudienceDelegate AudienceCheck(
        IOidcEndpointResolver resolver, TenantDefinition tenant)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => resolver);
        var issuerProvider = new Mock<IJwtBearerIssuerProvider>();
        issuerProvider.Setup(p => p.Options).Returns(new JwtBearerOptions());

        var policy = new JwtBearerAssertionPolicy(
            new Mock<ILogger<JwtBearerAssertionPolicy>>().Object,
            issuerProvider.Object,
            new FakeTimeProvider(),
            new Mock<IReplayCache>(MockBehavior.Strict).Object,
            new Mock<IRequestInfoProvider>(MockBehavior.Strict).Object,
            SingleIssuer.LicensedCatalog,
            services.BuildServiceProvider(validateScopes: true));

        return policy.ParametersFor(tenant, new ClientInfo("client")).ValidateAudience!;
    }
}
