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
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

public class ResourceInferenceTests
{
    private const string OrdersRead = "orders.read";
    private const string BillingRead = "billing.read";
    private const string Shared = "shared.read";

    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    private static ResourceInference Inference(bool infer) => new(SingleIssuer.SettingsOf(Options.Create(
        new OidcOptions
        {
            InferResourceFromScope = infer,
            Resources =
            [
                new ResourceDefinition(Orders, new ScopeDefinition(OrdersRead), new ScopeDefinition(Shared)),
                new ResourceDefinition(Billing, new ScopeDefinition(BillingRead), new ScopeDefinition(Shared)),
            ],
        })));

    /// <summary>
    /// The scopes refer to the one resource that declares one of them, whatever else they ask for.
    /// </summary>
    [Fact]
    public void ScopesReferringToOneResource_InferIt()
    {
        Assert.True(Inference(infer: true).TryInfer([Scopes.OpenId, OrdersRead], out var resource, out _));
        Assert.Equal(Orders, resource);
    }

    /// <summary>
    /// Scopes no resource declares infer nothing, so the request falls back as if inference were off.
    /// </summary>
    [Fact]
    public void ScopesNoResourceDeclares_InferNothing()
    {
        Assert.True(Inference(infer: true).TryInfer([Scopes.OpenId, Scopes.Profile], out var resource, out _));
        Assert.Null(resource);
    }

    /// <summary>
    /// Scopes referring to different resources are refused, whether two scopes name two resources or one scope is
    /// declared by both (RFC 9068 section 3).
    /// </summary>
    [Theory]
    [InlineData(OrdersRead, BillingRead)]
    [InlineData(Shared, Shared)]
    public void ScopesReferringToSeveralResources_AreRefused(string first, string second)
    {
        Assert.False(Inference(infer: true).TryInfer([first, second], out var resource, out var errorDescription));
        Assert.Null(resource);
        Assert.NotNull(errorDescription);
    }

    /// <summary>
    /// With inference off nothing is inferred and nothing refused, even for scopes that would be ambiguous.
    /// </summary>
    [Theory]
    [InlineData(OrdersRead)]
    [InlineData(Shared)]
    public void InferenceOff_InfersNothing(string scope)
    {
        Assert.True(Inference(infer: false).TryInfer([scope], out var resource, out _));
        Assert.Null(resource);
    }
}
