// Abblix OIDC Client Library
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

using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Principal;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.Principal;

/// <summary>
/// Turning a validated ID Token into the signed-in user.
/// </summary>
public class ClaimsPrincipalFactoryTests
{
    private const string Subject = "248289761001";

    private static ClaimsPrincipal Create(
        Action<JsonWebTokenPayload> configure,
        Action<ClaimsPrincipalOptions>? configureOptions = null)
    {
        var token = new JsonWebToken();
        token.Payload.Subject = Subject;
        configure(token.Payload);

        var options = new ClaimsPrincipalOptions();
        configureOptions?.Invoke(options);

        return new ClaimsPrincipalFactory(Options.Create(options)).Create(token);
    }

    /// <summary>
    /// The identity counts as authenticated. An identity with no authentication type is not, whatever claims
    /// it holds, and every authorization check would then reject a user who had just signed in successfully.
    /// </summary>
    [Fact]
    public void ThePrincipalIsAuthenticated()
    {
        var principal = Create(_ => { });

        Assert.True(principal.Identity?.IsAuthenticated);
    }

    /// <summary>
    /// The subject is the name by default, because it is the identifier OpenID Connect defines as stable for
    /// this end-user at this issuer.
    /// </summary>
    [Fact]
    public void TheSubjectIsTheNameByDefault()
    {
        var principal = Create(payload => payload["name"] = "Jane Doe");

        Assert.Equal(Subject, principal.Identity?.Name);
    }

    /// <summary>
    /// A host whose interface wants a friendlier name says which claim carries it.
    /// </summary>
    [Fact]
    public void TheNameClaimIsConfigurable()
    {
        var principal = Create(
            payload => payload["name"] = "Jane Doe",
            options => options.NameClaimType = "name");

        Assert.Equal("Jane Doe", principal.Identity?.Name);
    }

    /// <summary>
    /// Claims this library does not model are carried over too. A host that asked its provider for a claim
    /// should find it, rather than have the principal depend on what this version knows about.
    /// </summary>
    [Fact]
    public void UnmodelledClaimsAreCarriedOver()
    {
        var principal = Create(payload => payload["department"] = "payments");

        Assert.Equal("payments", principal.FindFirst("department")?.Value);
    }

    /// <summary>
    /// An array becomes several claims of one name, which is how a principal represents a multi-valued claim
    /// and what its role checks read.
    /// </summary>
    [Fact]
    public void AnArrayBecomesSeveralClaims()
    {
        var principal = Create(
            payload => payload["role"] = new JsonArray("admin", "auditor"),
            options => options.RoleClaimType = "role");

        Assert.True(principal.IsInRole("admin"));
        Assert.True(principal.IsInRole("auditor"));
    }

    /// <summary>
    /// A structured claim keeps its JSON rather than being flattened, so nothing the issuer meant is lost on
    /// the way into the principal.
    /// </summary>
    [Fact]
    public void AStructuredClaimKeepsItsJson()
    {
        var principal = Create(
            payload => payload["address"] = new JsonObject { ["country"] = "KZ" });

        var claim = principal.FindFirst("address");
        Assert.NotNull(claim);
        Assert.Equal("""{"country":"KZ"}""", claim.Value);
        Assert.Equal("JSON", claim.ValueType);
    }

    /// <summary>
    /// A number stays distinguishable from the string that looks like it, which a consumer would otherwise
    /// have to guess at.
    /// </summary>
    [Fact]
    public void ANumberIsRecordedAsOne()
    {
        var principal = Create(payload => payload["seat"] = 42);

        var claim = principal.FindFirst("seat");
        Assert.NotNull(claim);
        Assert.Equal("42", claim.Value);
        Assert.Equal(ClaimValueTypes.Double, claim.ValueType);
    }
}
