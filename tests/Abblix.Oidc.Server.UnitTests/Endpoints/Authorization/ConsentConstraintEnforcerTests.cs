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
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(capped));

        var enforced = await _enforcer.EnforceAsync(request, granted, CancellationToken.None);

        Assert.Same(capped, enforced);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsATypeTheUserDidNotGrant_Throws()
    {
        // The array that leaves this method is the one the grant is built from, so the type check has
        // to cover it - and against what the consent decision GRANTED, not merely against what was
        // requested. Here the user was asked about two types and granted one; an entry of the other
        // coming back from re-validation resurrects what they refused. It is the SECOND entry, because
        // a guard that stops at the first reads as working on every single-entry fixture.
        var request = CreateRequest(authorizationDetails: new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(new JsonArray(
                new JsonObject { ["type"] = "payment_initiation" },
                new JsonObject { ["type"] = "account_information" })));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Contains("account_information", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsAnEntryWithoutAType_Throws()
    {
        // A missing type passes "not among the types nobody granted" by being unreadable, and RFC 9396
        // section 2 makes type REQUIRED on every entry - so the answer is a refusal, not a skip. Change the
        // type and the guard refuses; delete it and it must not wave the entry through.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(
                new JsonArray(new JsonObject { ["amount"] = "999999" })));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
    }

    [Fact]
    public async Task EnforceAsync_GrantedCarriesAnEntryThatIsNotAnObject_Throws()
    {
        // The guard reads entries through a conversion that DROPS anything that is not an object, so a
        // shorter result would let it report "no escaped types" about an array it could not read.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails: new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            JsonValue.Create("payment_initiation")));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        // Refused before the policy is consulted: it is the guard's own reading that failed.
        _authorizationDetailsPolicy.Verify(
            p => p.ApplyGrantedAsync(It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsAnEntryWithoutATypeAndTheRequestNamedTheStandIn_Throws()
    {
        // A missing type must not be compared as a value. If it were folded into a stand-in string, a
        // client could ask for a type spelled exactly that way and thereby admit every typeless entry
        // the validators return - the guard would read them as a type the request carried.
        const string standIn = "(no type)";

        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = standIn }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = standIn }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(new JsonArray(
                new JsonObject { ["type"] = standIn },
                new JsonObject { ["amount"] = "999999" })));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsSeveralEntriesAndOneEscapes_Throws()
    {
        // The granted array here has two entries, so a guard that read only the first would pass. The
        // escaping entry is the second on BOTH sides, which is the shape a single-entry fixture cannot
        // tell apart from a guard that works.
        var request = CreateRequest(authorizationDetails: new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" }));
        var granted = Granted(authorizationDetails: new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(new JsonArray(
                new JsonObject { ["type"] = "payment_initiation" },
                new JsonObject { ["type"] = "admin_access" })));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Contains("admin_access", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsAnEntryThatIsNotAnObject_Throws()
    {
        // The shape guard has to cover the array that LEAVES, not only the one that arrived: the entry
        // the caller emits is the policy's output, and the conversion the guard reads through drops a
        // non-object silently.
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(new JsonArray(
                new JsonObject { ["type"] = "payment_initiation" },
                JsonValue.Create("payment_initiation"))));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
    }

    [Fact]
    public async Task EnforceAsync_ValidatorEditsTheTypeInPlaceAndReturnsNothing_Throws()
    {
        // Every narrowing validator in this repository's own fixtures edits the entry IN PLACE and
        // returns the same wrapper, and the typed wrappers alias the source nodes - so a policy that
        // answers "nothing to change" can still have rewritten the array it was handed. The types read
        // before the call are the only untouched copy, and that path has to be guarded too.
        var grantedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails: grantedAd);

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((JsonArray? ad, ClientInfo _, CancellationToken _) =>
            {
                ad![0]!["type"] = "wire_transfer";
                return Result<JsonArray?, OidcError>.Success(null);
            });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));

        Assert.Contains("wire_transfer", ex.Message);
    }

    [Fact]
    public async Task EnforceAsync_PolicyReturnsAnEmptySet_Throws()
    {
        // Null and empty are different statements. Empty says every entry was removed, and this same
        // request answers access_denied to a consent decision that granted none - so emitting the
        // granted set here would put back exactly what the validators took out.
        var grantedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails:
            new JsonArray(new JsonObject { ["type"] = "payment_initiation" }));
        var granted = Granted(authorizationDetails: grantedAd);

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<JsonArray?, OidcError>.Success(new JsonArray()));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enforcer.EnforceAsync(request, granted, CancellationToken.None));
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
            .Setup(p => p.ApplyGrantedAsync(
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
            => Task.FromResult(
                detail.Json["access"]?["accounts"] is JsonArray { Count: > 0 }
                    ? Refuse("access.accounts is chosen by the end-user, so a request must leave it empty")
                    : SharedRules(detail));

        // Only the enrichable field is exempt. Everything else this type refuses, it refuses in both
        // phases, because a consent decision that crossed the browser is not more trusted than a client.
        public Task<Result<AuthorizationDetail, OidcError>> ValidateGrantedAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult(SharedRules(detail));

        private static Result<AuthorizationDetail, OidcError> SharedRules(AuthorizationDetail detail)
            => detail.Json["access"] is JsonObject
                ? detail
                : Refuse("access is required for account_information");

        private static Result<AuthorizationDetail, OidcError> Refuse(string description)
            => new OidcError(ErrorCodes.InvalidAuthorizationDetails, description);
    }
}
