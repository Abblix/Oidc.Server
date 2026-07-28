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
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

public class AuthorizationContextExtensionsTests
{
    [Fact]
    public void SerializeDeserializeTest()
    {
        var ac = new AuthorizationContext(
            "clientId",
            ["scope1", "scope2"],
            new RequestedClaims { UserInfo = new Dictionary<string, RequestedClaimDetails>
            {
                { "abc", new RequestedClaimDetails { Essential = true } },
            }});

        var payload = new JsonWebTokenPayload(new JsonObject());
        ac.ApplyTo(payload);
        Assert.Contains(payload.Json, claim => claim.Key == "requested_claims");

        var ac2 = payload.ToAuthorizationContext();
        Assert.NotNull(ac2.RequestedClaims);
        Assert.NotNull(ac2.RequestedClaims.UserInfo);
        Assert.True(ac2.RequestedClaims.UserInfo["abc"].Essential);
    }

    [Fact]
    public void Resources_RoundTrip_Through_AudienceClaim()
    {
        // RFC 8707 resource indicators are emitted into the aud claim and reconstructed back into
        // Resources when the token is re-read (e.g. on refresh). This pins both ApplyTo and
        // ToAuthorizationContext, which are the two halves of the resource <-> aud mapping.
        var resources = new[] { new Uri("https://api1.example.com/"), new Uri("https://api2.example.com/") };
        var ac = new AuthorizationContext("clientId", ["scope1"], null, resources);

        var payload = new JsonWebTokenPayload(new JsonObject());
        ac.ApplyTo(payload);

        Assert.Equal(
            new[] { "https://api1.example.com/", "https://api2.example.com/" },
            payload.Audiences.ToArray());

        var ac2 = payload.ToAuthorizationContext();
        Assert.Equal(resources, ac2.Resources);
    }

    [Fact]
    public void NoResources_AudienceFallsBackToClientId()
    {
        // With no resource indicator the OIDC convention puts the client id in aud; re-reading such
        // a token yields no resources (a single client-id audience is not treated as a resource).
        var ac = new AuthorizationContext("clientId", ["scope1"], null);

        var payload = new JsonWebTokenPayload(new JsonObject());
        ac.ApplyTo(payload);

        Assert.Equal(["clientId"], payload.Audiences.ToArray());

        var ac2 = payload.ToAuthorizationContext();
        Assert.Null(ac2.Resources);
    }

    // WithDefaultResource: RFC 9068 section 3 wants a default resource indicator in aud when the request
    // names none, instead of the client identifier, which names the party that asked rather than the one
    // meant to consume the token.

    private static readonly Uri DefaultApi = new("https://api.example.com");

    /// <summary>
    /// A context naming no audience takes the configured default, so the token says who it is for.
    /// </summary>
    [Fact]
    public void WithDefaultResource_NoAudienceNamed_TakesTheDefault()
    {
        var context = new AuthorizationContext("clientId", ["scope1"], null);

        var result = context.WithDefaultResource(DefaultApi);

        Assert.NotNull(result.Resources);
        Assert.Equal([DefaultApi], result.Resources);

        var payload = new JsonWebTokenPayload(new JsonObject());
        result.ApplyTo(payload);
        Assert.Equal([DefaultApi.OriginalString], payload.Audiences.ToArray());
    }

    /// <summary>
    /// Supplying no default leaves the context alone, which is what every host that has not opted in gets:
    /// the audience still falls back to the client identifier exactly as before.
    /// </summary>
    [Fact]
    public void WithDefaultResource_NoDefaultConfigured_LeavesContextUnchanged()
    {
        var context = new AuthorizationContext("clientId", ["scope1"], null);

        var result = context.WithDefaultResource(null);

        Assert.Same(context, result);
        Assert.Null(result.Resources);
    }

    /// <summary>
    /// A request that named a resource already says who the token is for, so the default does not override it.
    /// </summary>
    [Fact]
    public void WithDefaultResource_ResourceAlreadyNamed_LeavesContextUnchanged()
    {
        var requested = new Uri("https://orders.example.com");
        var context = new AuthorizationContext("clientId", ["scope1"], null) { Resources = [requested] };

        var result = context.WithDefaultResource(DefaultApi);

        Assert.Same(context, result);
        Assert.NotNull(result.Resources);
        Assert.Equal([requested], result.Resources);
    }

    /// <summary>
    /// The same holds for an audience named through RFC 8693 token exchange, which is the other way a request
    /// states its intended consumer.
    /// </summary>
    [Fact]
    public void WithDefaultResource_AudienceAlreadyNamed_LeavesContextUnchanged()
    {
        var context = new AuthorizationContext("clientId", ["scope1"], null) { Audiences = ["urn:orders"] };

        var result = context.WithDefaultResource(DefaultApi);

        Assert.Same(context, result);
        Assert.Null(result.Resources);
    }
}
