// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationEndpointMetadataFactory"/> verifying that the discovery metadata
/// (response types, request/claims parameter support) is derived from the registered response builders.
/// </summary>
public class AuthorizationEndpointMetadataFactoryTests
{
    private static IAuthorizationResponseBuilder Builder(string responseType)
        => Mock.Of<IAuthorizationResponseBuilder>(p => p.ResponseType == responseType);

    /// <summary>
    /// All three response builders registered (mirroring <c>EnableImplicitFlow()</c>).
    /// </summary>
    private static AuthorizationEndpointMetadata ImplicitFlowEnabled()
        => AuthorizationEndpointMetadataFactory.Create(
            [Builder(ResponseTypes.Code), Builder(ResponseTypes.Token), Builder(ResponseTypes.IdToken)]);

    /// <summary>
    /// Only the Code builder registered, mirroring the default (<c>EnableImplicitFlow()</c> not called).
    /// </summary>
    private static AuthorizationEndpointMetadata ImplicitFlowDisabled()
        => AuthorizationEndpointMetadataFactory.Create([Builder(ResponseTypes.Code)]);

    /// <summary>
    /// Verifies metadata indicates request parameter support.
    /// Per JAR (RFC 9101), request parameter should be advertised.
    /// </summary>
    [Fact]
    public void Create_ShouldIndicateRequestParameterSupported()
    {
        Assert.True(ImplicitFlowEnabled().RequestParameterSupported);
    }

    /// <summary>
    /// Verifies metadata indicates claims parameter support.
    /// Per OIDC Core Section 5.5, claims parameter support should be advertised.
    /// </summary>
    [Fact]
    public void Create_ShouldIndicateClaimsParameterSupported()
    {
        Assert.True(ImplicitFlowEnabled().ClaimsParameterSupported);
    }

    /// <summary>
    /// Verifies that without <c>EnableImplicitFlow()</c>, the discovery document advertises only
    /// the <c>code</c> response type; <c>token</c>, <c>id_token</c>, and the four hybrid
    /// combinations are absent. Per OAuth 2.1 section 1.4 default-off Implicit Flow contract.
    /// </summary>
    [Fact]
    public void Create_ResponseTypesSupported_WhenImplicitFlowDisabled_ContainsOnlyCode()
    {
        Assert.Equal([ResponseTypes.Code], ImplicitFlowDisabled().ResponseTypesSupported);
    }

    /// <summary>
    /// Verifies that when <c>EnableImplicitFlow()</c> is in effect (all three response-type builders
    /// registered), the discovery document advertises every canonical RFC-defined response-type
    /// combination: the three single parts and the four hybrid combinations.
    /// </summary>
    [Fact]
    public void Create_ResponseTypesSupported_WhenImplicitFlowEnabled_ContainsAllSevenCombinations()
    {
        Assert.Equal(
            new[]
            {
                ResponseTypes.Code,
                ResponseTypes.Token,
                ResponseTypes.IdToken,
                $"{ResponseTypes.Code} {ResponseTypes.Token}",
                $"{ResponseTypes.Code} {ResponseTypes.IdToken}",
                $"{ResponseTypes.Token} {ResponseTypes.IdToken}",
                $"{ResponseTypes.Code} {ResponseTypes.Token} {ResponseTypes.IdToken}",
            },
            ImplicitFlowEnabled().ResponseTypesSupported);
    }

    /// <summary>
    /// With the none response builder registered (<c>EnableNoneFlow()</c>), the discovery
    /// document advertises the <c>none</c> response type alongside the others.
    /// </summary>
    [Fact]
    public void Create_ResponseTypesSupported_WhenNoneEnabled_ContainsNone()
    {
        var metadata = AuthorizationEndpointMetadataFactory.Create(
            [Builder(ResponseTypes.Code), Builder(ResponseTypes.None)]);

        Assert.Contains(ResponseTypes.None, metadata.ResponseTypesSupported);
    }

    /// <summary>
    /// Without the none response builder, <c>none</c> is absent from <c>response_types_supported</c>.
    /// </summary>
    [Fact]
    public void Create_ResponseTypesSupported_WhenNoneDisabled_OmitsNone()
    {
        Assert.DoesNotContain(ResponseTypes.None, ImplicitFlowDisabled().ResponseTypesSupported);
    }
}
