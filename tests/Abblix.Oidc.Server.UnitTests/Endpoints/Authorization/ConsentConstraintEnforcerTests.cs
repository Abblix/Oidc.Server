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
using Abblix.Jwt;
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
using Microsoft.Extensions.DependencyInjection;
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
            .Setup(p => p.ApplyGrantedAsync(
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
            p => p.ApplyGrantedAsync(It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()),
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
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Failure(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, "amount exceeds the client's cap")));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
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

    [Fact]
    public async Task EnforceAsync_ConsentEnrichedTheEntry_DoesNotThrow()
    {
        // RFC 9396 section 7.1, worked in Figures 16 and 17: the client asks for account information
        // with empty placeholders, the user picks the accounts, and the server writes the identifiers
        // in. A validator implementing section 5 refuses populated placeholders in a REQUEST, because
        // the client must not choose the accounts - so re-running the granted entry through the
        // request-time question rejects what the specification says the server may do.
        //
        // A real composite policy, not a mock: the permissive stub is what kept this green.
        var services = new ServiceCollection();
        services.AddRichAuthorizationRequests();
        services.AddAuthorizationDetailValidator<PlaceholderAccountValidator>(
            PlaceholderAccountValidator.AccountInformation);
        var enforcer = new ConsentConstraintEnforcer(
            services.BuildServiceProvider().GetRequiredService<IAuthorizationDetailsPolicy>());

        var request = CreateRequest(authorizationDetails: new JsonArray(
            new JsonObject
            {
                ["type"] = PlaceholderAccountValidator.AccountInformation,
                ["access"] = new JsonObject { ["accounts"] = new JsonArray() },
            }));

        var granted = Granted(authorizationDetails: new JsonArray(
            new JsonObject
            {
                ["type"] = PlaceholderAccountValidator.AccountInformation,
                ["access"] = new JsonObject
                {
                    ["accounts"] = new JsonArray(
                        new JsonObject { ["iban"] = "DE2310010010123456789" }),
                },
            }));

        var exception = await Record.ExceptionAsync(
            () => enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Null(exception);
    }

    /// <summary>
    /// A conforming validator for an enrichable type: it refuses a request whose placeholders are
    /// already filled (RFC 9396 section 5, "invalid values for the authorization details type"), and
    /// accepts the filled shape once the consent decision produced it (section 7.1).
    /// </summary>
    private sealed class PlaceholderAccountValidator : IAuthorizationDetailValidator
    {
        public const string AccountInformation = "account_information";

        public string Type => AccountInformation;

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(
                detail.Json["access"]?["accounts"] is JsonArray { Count: > 0 }
                    ? new OidcError(
                        ErrorCodes.InvalidAuthorizationDetails,
                        "access.accounts is chosen by the end-user, so a request must leave it empty")
                    : detail);

        public Task<Result<AuthorizationDetail, OidcError>> ValidateGrantedAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }
}
