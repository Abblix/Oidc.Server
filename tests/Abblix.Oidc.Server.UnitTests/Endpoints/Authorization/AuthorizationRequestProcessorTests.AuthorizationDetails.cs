// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    // ───────────────────────────────────────────────────────────────────────
    // RFC 9396 - consent capture for authorization_details (#142).
    // The Pending bucket surfaces AD entries to the consent UI; the Granted
    // bucket carries the user's decision (which may narrow or deny the
    // request); token emission reads from Granted, with null → request
    // fallback for backward compatibility with PR #135 hosts.
    // ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures the <see cref="AuthorizedGrant"/> passed to
    /// <see cref="IAuthorizationCodeService.GenerateAuthorizationCodeAsync"/>. Tests
    /// inspect the captured grant's <see cref="AuthorizationContext"/> to assert what
    /// the processor emitted into the token-issuance path.
    /// </summary>
    private sealed class GrantCapture
    {
        public AuthorizedGrant? Grant { get; set; }
    }

    /// <summary>
    /// Wires up the strict Mocks for a successful authorization-code flow and returns a
    /// <see cref="GrantCapture"/> that fills in once <see cref="AuthorizationRequestProcessor.ProcessAsync"/>
    /// reaches the code-issuance step. Eliminates the four-line Setup boilerplate from
    /// each consent-side test.
    /// </summary>
    private GrantCapture SetupSuccessfulAuthCodeFlow(
        ValidAuthorizationRequest request,
        AuthSession session,
        UserConsents consents)
    {
        var capture = new GrantCapture();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .Callback<AuthorizedGrant, TimeSpan>((grant, _) => capture.Grant = grant)
            .ReturnsAsync("code");

        return capture;
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsPendingForConsent_ReturnsConsentRequired()
    {
        var pendingAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: pendingAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingAuthorizationDetails: pendingAd);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Same(pendingAd, consentRequired.RequiredUserConsents.AuthorizationDetails);
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsAllDenied_ReturnsAccessDenied()
    {
        // Provider returned Granted.AuthorizationDetails = [] (empty, not null) while the
        // request carried AD entries -- the canonical "user denied every entry" signal.
        var requestedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: new JsonArray());

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    /// <summary>
    /// A consent provider that empties the request as it answers is still answered with a denial.
    /// </summary>
    /// <remarks>
    /// The provider is a host seam, and it is handed the array the request carries - so a provider that
    /// narrows by editing what it was given, which is how narrowing is written everywhere in this
    /// repository, empties the very set the denial is measured against. Measured afterwards, the request
    /// looks like one that never asked for anything, the denial turns into a successful authorization,
    /// and the token carries no authorization_details at all - which neither the client nor the resource
    /// server can detect.
    /// </remarks>
    [Fact]
    public async Task ProcessAsync_AConsentProviderEmptyingTheRequestInPlace_StillReturnsAccessDenied()
    {
        var requestedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: new JsonArray());

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .Callback(() => requestedAd.Clear())
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsNarrowedByProvider_PropagatesNarrowToContext()
    {
        // Provider returns a narrower Granted.AuthorizationDetails than the request carried
        // -- the AuthorizationContext (and downstream token emission) reflects the narrow set.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500.00" });
        var narrowedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "200.00" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: narrowedAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): the AuthorizationContext receives a clone,
        // not the same reference -- assert value-equality through the wire JSON instead.
        Assert.Equal(narrowedAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task ProcessAsync_PolicyNormalisesGrantedDetails_TokenReflectsTheNormalisedSet()
    {
        // The request already carries the capped amount, because the request-time validator narrowed
        // it before consent was asked. A provider that rebuilds its granted array from the original
        // client request hands back the uncapped one; its type was requested, so the type-level subset
        // check passes, and the per-type validator answers by RETURNING the capped entry rather than
        // by failing - which is how a normalising validator says "this far and no further".
        // Emitting the provider's number instead of the returned one would put an amount in the token
        // that no validator ever approved.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "1000" });
        var grantedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "5000" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: grantedAd);

        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((JsonArray? ad, JsonArray? _, ClientInfo _, CancellationToken _) =>
                CapAmount(ad, 800m) ?? new JsonArray());

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        var emitted = capture.Grant.Context.AuthorizationDetails!;
        Assert.Equal("800", emitted[0]!["amount"]!.GetValue<string>());
    }

    /// <summary>
    /// A normalising per-type validator: over the cap it returns a capped CLONE rather than mutating
    /// the entry it was handed, which is what makes the returned value the only place the decision lives.
    /// </summary>
    private static JsonArray? CapAmount(JsonArray? details, decimal cap)
    {
        if (details is null)
            return null;

        var capped = new JsonArray();
        foreach (var entry in details)
        {
            var clone = (JsonObject)entry!.DeepClone();
            var parsed = decimal.TryParse(
                clone["amount"]?.GetValue<string>(),
                NumberStyles.Number,
                CultureInfo.InvariantCulture,
                out var amount);

            if (parsed && amount > cap)
                clone["amount"] = cap.ToString(CultureInfo.InvariantCulture);

            capped.Add(clone);
        }

        return capped;
    }

    [Fact]
    public async Task ProcessAsync_ConsentDropsOneEntryFromMultiSet_TokenReflectsRemaining()
    {
        // RFC 9396 section 3 notes the user may grant a subset of what was requested, and section 7 then has the
        // server return what was granted. Client requested two entries, user
        // agreed to one. Consent layer is the right surface for this -- per-type
        // validators only see a single entry and cannot reason cross-entry.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" });
        var partialAd = new JsonArray(
            new JsonObject { ["type"] = "account_information" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: partialAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): value-equality, not reference.
        Assert.Equal(partialAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
        Assert.Single(capture.Grant.Context.AuthorizationDetails!);
    }

    [Fact]
    public async Task ProcessAsync_ConsentAppliesCrossDetailCapAcrossEntries_TokenReflectsCappedSet()
    {
        // The same section 3 note read across entries rather than within one. Client requested three
        // payment_initiation
        // entries of 500 each (total 1500); host policy caps total at 1000; consent
        // provider sees the entire list and returns the cross-cut narrow with the
        // last entry zeroed out. Per-type validators have no signal that the third
        // entry tips over the cap; consent layer does.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" });
        var cappedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "0" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: cappedAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        var emitted = capture.Grant.Context.AuthorizationDetails!;
        Assert.Equal(3, emitted.Count);
        Assert.Equal("0", emitted[2]!["amount"]!.GetValue<string>());
    }

    [Fact]
    public async Task ProcessAsync_LegacyProviderReturnsNullGrantedAd_FallsBackToRequestValue()
    {
        // Backward compat: a provider that has not been updated for #142 leaves
        // Granted.AuthorizationDetails as null. Emission falls back to the request's
        // (post-validator) AuthorizationDetails so PR #135 behavior is preserved.
        var requestedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents();

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): value-equality, not reference.
        Assert.Equal(requestedAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
    }
}
