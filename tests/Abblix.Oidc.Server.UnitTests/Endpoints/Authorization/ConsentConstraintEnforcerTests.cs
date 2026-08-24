// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="ConsentConstraintEnforcer"/> (#185): the anti-escalation backstop
/// asserts the consent decision is a subset of the request and throws when it is not, since a
/// broader granted set is a host-side <see cref="IUserConsentsProvider"/> contract violation.
/// </summary>
public class ConsentConstraintEnforcerTests
{
    private const string ClientId = "test-client";

    private readonly Mock<IAuthorizationDetailsPolicy> _authorizationDetailsPolicy =
        new(MockBehavior.Strict);
    private readonly ConsentConstraintEnforcer _enforcer;

    public ConsentConstraintEnforcerTests()
    {
        _enforcer = new ConsentConstraintEnforcer(_authorizationDetailsPolicy.Object);
    }

    private static ValidAuthorizationRequest CreateRequest(
        ScopeDefinition[]? scopes = null,
        ResourceDefinition[]? resources = null,
        JsonArray? authorizationDetails = null)
    {
        var model = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/cb"),
        };

        return new ValidAuthorizationRequest(new AuthorizationValidationContext(model)
        {
            ClientInfo = new ClientInfo(ClientId),
            ResponseMode = ResponseModes.Query,
            Scope = scopes ?? [new ScopeDefinition(Scopes.OpenId)],
            Resources = resources ?? [],
            AuthorizationDetails = authorizationDetails,
        });
    }

    private static ConsentDefinition Granted(
        ScopeDefinition[]? scopes = null,
        ResourceDefinition[]? resources = null,
        JsonArray? authorizationDetails = null)
        => new(scopes ?? [new ScopeDefinition(Scopes.OpenId)], resources ?? [])
        {
            AuthorizationDetails = authorizationDetails,
        };

    private void SetupPolicyPassThrough() =>
        _authorizationDetailsPolicy
            .Setup(p => p.ApplyAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((JsonArray? ad, ClientInfo _, CancellationToken _) =>
                Result<JsonArray?, OidcError>.Success(ad));

    [Fact]
    public async Task EnforceAsync_GrantedEqualsRequested_DoesNotThrow()
    {
        var request = CreateRequest(scopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition(Scopes.Profile)]);
        var granted = Granted(scopes: [new ScopeDefinition(Scopes.OpenId)]);

        var exception = await Record.ExceptionAsync(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Null(exception);
    }

    [Fact]
    public async Task EnforceAsync_GrantedScopeNotRequested_Throws()
    {
        var request = CreateRequest(scopes: [new ScopeDefinition(Scopes.OpenId)]);
        var granted = Granted(scopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("admin")]);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
        Assert.Contains("admin", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_GrantedResourceNotRequested_Throws()
    {
        var request = CreateRequest();
        var granted = Granted(resources: [new ResourceDefinition(new Uri("https://api.example/admin"))]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
    }

    [Fact]
    public async Task EnforceAsync_GrantedResourceScopeExceedsRequested_Throws()
    {
        var resource = new Uri("https://api.example/payments");
        // The resource itself is requested, but the granted nested scope set is broader.
        var request = CreateRequest(resources: [new ResourceDefinition(resource, new ScopeDefinition("read"))]);
        var granted = Granted(resources:
            [new ResourceDefinition(resource, new ScopeDefinition("read"), new ScopeDefinition("write"))]);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
        Assert.Contains("write", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_GrantedAuthorizationDetailsTypeNotRequested_Throws()
    {
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "account_information" }));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
        Assert.Contains("account_information", ex.Message);

        // The type-level subset check fails before any per-type re-validation is attempted.
        _authorizationDetailsPolicy.Verify(
            p => p.ApplyAsync(It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task EnforceAsync_GrantedAuthorizationDetailsFailRevalidation_Throws()
    {
        var ad = new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "999" });
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "100" }));
        var granted = Granted(authorizationDetails: ad);

        // The per-type policy rejects the granted entry (e.g. amount escalated beyond the client's cap).
        _authorizationDetailsPolicy
            .Setup(p => p.ApplyAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Failure(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, "amount exceeds the client's cap")));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
    }

    [Fact]
    public async Task EnforceAsync_PolicyNormalisesGrantedDetails_ReturnsWhatThePolicyReturned()
    {
        // A per-type validator that narrows by RETURNING a capped entry is making the decision in its
        // return value, so the enforcer must hand that value on. Returning the granted array instead
        // would leave the cap behind in a variable nobody reads.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "1000" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "5000" }));
        var capped = new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "1000" });

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(capped));

        var enforced = await _enforcer.EnforceAsync(request, granted, CancellationToken.None);

        Assert.Same(capped, enforced);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsAnUnrequestedType_Throws()
    {
        // The array that leaves this method is the one the grant is built from, so the type check has
        // to cover it. Nothing in the per-type validator's contract stops the entry it returns from
        // carrying a different type than the one it was asked about, and an entry whose type nobody
        // requested is the escalation this backstop exists to refuse.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(
                new JsonArray(new JsonObject { ["type"] = "admin_access" })));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Contains("admin_access", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsNothing_KeepsTheGrantedSet()
    {
        // A null result means "nothing to change" everywhere else this policy is consumed - the
        // request-time, CIBA and device validators all keep what they had - so reading it here as
        // "the validators emptied the set" would drop authorization_details RFC 9396 section 7
        // obliges the server to return, on a path where nobody can tell.
        var grantedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails: grantedAd);

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(null));

        var enforced = await _enforcer.EnforceAsync(request, granted, CancellationToken.None);

        Assert.Same(grantedAd, enforced);
    }

    [Fact]
    public async Task EnforceAsync_GrantedCarriesNoAuthorizationDetails_ReturnsNull()
    {
        // Null is how a consent provider says it has no authorization_details opinion at all, and the
        // caller keys its fall-back to the request on exactly that. The policy is never consulted,
        // which the strict mock asserts by construction.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted();

        var enforced = await _enforcer.EnforceAsync(request, granted, CancellationToken.None);

        Assert.Null(enforced);
    }

    [Fact]
    public async Task EnforceAsync_GrantedAuthorizationDetailsValidNarrowing_DoesNotThrow()
    {
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation", ["amount"] = "200" }));
        SetupPolicyPassThrough();

        var exception = await Record.ExceptionAsync(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Null(exception);
    }
}
