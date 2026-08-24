// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.AuthorizationDetails;

/// <summary>
/// Unit tests for the composite <see cref="IAuthorizationDetailsPolicy"/> registered via
/// <c>AddRichAuthorizationRequests()</c>. Covers dispatch by <c>type</c>, RFC 9396 §5 unknown-type
/// rejection, per-type-validator failure propagation, and the graceful-degradation contract
/// (server boots cleanly with zero per-type validators registered).
/// </summary>
public class AuthorizationDetailsPolicyTests
{
    private static readonly ClientInfo TestClient = new("test-client");

    [Fact]
    public void Composite_resolves_with_zero_per_type_validators_registered()
    {
        var sp = BuildProvider();

        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();

        Assert.NotNull(composite);
    }

    [Fact]
    public async Task Unknown_type_yields_invalid_authorization_details_failure()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains("payment_initiation", error.ErrorDescription);
        Assert.Contains("unknown", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Missing_type_member_yields_failure()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        // RFC 9396 §2: the 'type' member is required. Entry without it must reject.
        var raw = new JsonArray(new JsonObject());

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains("type", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// An authorization_details array whose entries are not JSON objects is refused, not quietly reduced
    /// to nothing.
    /// </summary>
    /// <remarks>
    /// The conversion drops what it cannot read, and the emptiness it leaves behind is indistinguishable
    /// from the client having sent no authorization_details at all - so the request used to be authorized
    /// with its RAR grant discarded, which neither the client nor the resource server can detect. RFC 9396
    /// section 2 defines the entries as JSON objects, so this is a malformed request and has a named answer.
    /// </remarks>
    [Theory]
    [InlineData("payment_initiation")]
    [InlineData(7)]
    public async Task Entries_that_are_not_objects_yield_failure(object element)
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(JsonValue.Create(element));

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
    }

    /// <summary>
    /// A 'type' member carrying something other than a string is refused in protocol language, not by an
    /// exception escaping the endpoint.
    /// </summary>
    /// <remarks>
    /// The regression test for an HTTP 500 reachable before authentication: authorization_details is
    /// carried as schemaless JSON, so this entry survives every earlier shape check, and reading its type
    /// used to throw straight out of the accessor. RFC 9396 section 5 already names the answer, and the
    /// entry ends up refused for the same reason a missing type is - it states none.
    /// The assertion is the refusal rather than the absence of a throw. A test that only required "does
    /// not throw" would pass just as well against a version that quietly authorized the request with the
    /// authorization_details dropped, which is the other way this could have been got wrong.
    /// </remarks>
    [Theory]
    [InlineData(123)]
    [InlineData(true)]
    public async Task Type_member_of_the_wrong_json_type_yields_failure(object value)
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(new JsonObject { ["type"] = JsonValue.Create(value) });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains("type", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Single_validator_dispatched_by_type_returns_validated_detail()
    {
        var sp = BuildProvider(registerValidators: services =>
            services.AddAuthorizationDetailValidator<StubValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(new JsonObject
        {
            ["type"] = "payment_initiation",
            ["actions"] = new JsonArray("initiate"),
        });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        var entry = Assert.Single(validated!);
        Assert.Equal("payment_initiation", entry!["type"]!.GetValue<string>());
    }

    [Fact]
    public async Task Multiple_validators_dispatched_in_order_on_success()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation")
            .AddAuthorizationDetailValidator<AccountValidator>("account_information"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        Assert.Equal(2, validated!.Count);
        Assert.Equal("payment_initiation", validated[0]!["type"]!.GetValue<string>());
        Assert.Equal("account_information", validated[1]!["type"]!.GetValue<string>());
    }

    [Fact]
    public async Task Per_type_validator_failure_propagates_through_composite()
    {
        var sp = BuildProvider(registerValidators: services =>
            services.AddAuthorizationDetailValidator<RejectingValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(RejectingValidator.Reason, error.ErrorDescription);
    }

    [Fact]
    public async Task First_failure_short_circuits_remaining_validation()
    {
        var counter = new InvocationCounter();
        var sp = BuildProvider(registerValidators: services =>
        {
            services.AddSingleton(counter);
            services
                .AddAuthorizationDetailValidator<RejectingValidator>("payment_initiation")
                .AddAuthorizationDetailValidator<CountingValidator>("account_information");
        });
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out _));
        Assert.Equal(0, counter.Count);
    }

    [Fact]
    public async Task Lookup_resolves_in_constant_time_by_type_key()
    {
        // Three validators, three keyed lookups; each dispatch finds the matching impl in O(1).
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation")
            .AddAuthorizationDetailValidator<AccountValidator>("account_information")
            .AddAuthorizationDetailValidator<StubValidator>("consent"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(
            new JsonObject { ["type"] = "consent" },
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" });

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        Assert.Equal(
            ["consent", "payment_initiation", "account_information"],
            validated!.Select(node => node!["type"]!.GetValue<string>()).ToArray());
    }

    [Fact]
    public async Task ApplyAsync_returns_null_when_raw_is_null_or_empty()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();

        var resultNull = await composite.ApplyAsync(null, TestClient, TestContext.Current.CancellationToken);
        Assert.True(resultNull.TryGetSuccess(out var validatedNull));
        Assert.Null(validatedNull);

        var resultEmpty = await composite.ApplyAsync(new JsonArray(), TestClient, TestContext.Current.CancellationToken);
        Assert.True(resultEmpty.TryGetSuccess(out var validatedEmpty));
        Assert.Null(validatedEmpty);
    }

    [Fact]
    public async Task ApplyAsync_rejects_when_client_allowlist_is_empty()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var client = new ClientInfo("c") { AuthorizationDetailsTypes = [] };
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyAsync(raw, client, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains("not permitted", error.ErrorDescription);
    }

    [Fact]
    public async Task ApplyAsync_rejects_type_not_in_client_allowlist()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation")
            .AddAuthorizationDetailValidator<AccountValidator>("account_information"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var client = new ClientInfo("c") { AuthorizationDetailsTypes = ["account_information"] };
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyAsync(raw, client, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains("payment_initiation", error.ErrorDescription);
    }

    [Fact]
    public async Task ApplyAsync_null_allowlist_skips_per_client_check_and_dispatches()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var client = new ClientInfo("c") { AuthorizationDetailsTypes = null };
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyAsync(raw, client, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        Assert.Equal(raw.ToJsonString(), validated!.ToJsonString());
    }

    // ───────────────────────────────────────────────────────────────────────
    // RFC 9396 §7.1 validator-side mutation pipeline. Per-type validators see
    // one entry at a time and may narrow or normalise it; mutations propagate
    // through ApplyAsync's rebuild from the validated typed list. Cross-entry
    // policy (drop-entry, total-amount cap across the whole list) is the
    // consent layer's responsibility (#142) -- IUserConsentsProvider sees the
    // full Granted.AuthorizationDetails and can subset / cap arbitrarily.
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Scenario1_consent_slider_narrows_amount_from_500_to_200()
    {
        // Client requests "transfer 500 EUR"; user moves the slider on the consent
        // UI to 200; the per-type validator narrows the entry to amount=200, the
        // composite rebuilds the raw array with the narrowed shape, the access
        // token carries 200 - not 500. Without this, the AS would have to either
        // emit 500 (over-grant, vulnerability) or reject the whole request.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<NarrowToTwoHundredValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        const string inputWire =
            """[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        var raw = (JsonArray)JsonNode.Parse(inputWire)!;

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        var wire = validated!.ToJsonString();
        Assert.Contains("\"amount\":\"200.00\"", wire);
        Assert.DoesNotContain("500.00", wire);
    }

    [Fact]
    public async Task Scenario2_client_tier_cap_narrows_5000_to_1000_when_request_exceeds_limit()
    {
        // Client belongs to a "basic" tier with a per-transaction cap of 1000 EUR.
        // It requests 5000. Without mutation the AS would have to reject - but the
        // client doesn't know the tier limit, so it can't retry meaningfully. With
        // mutation the validator narrows to 1000; user sees a single consent screen
        // with "approved up to 1000 instead of 5000" and the token carries 1000.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<TierCap1000Validator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        const string inputWire =
            """[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"5000.00"}}]""";
        var raw = (JsonArray)JsonNode.Parse(inputWire)!;

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        var wire = validated!.ToJsonString();
        Assert.Contains("\"amount\":\"1000.00\"", wire);
        Assert.DoesNotContain("5000.00", wire);
    }

    [Fact]
    public async Task Scenario4_canonicalisation_dedupes_and_lowercases_actions()
    {
        // Client sends actions: ["initiate", "Initiate", "INITIATE"] (mixed-case
        // duplicates). Without mutation the AS would either reject ("duplicate
        // action") or accept ambiguously, leaving the resource server to deal with
        // multiple representations of the same action. With mutation the validator
        // normalises to a canonical lowercase deduped list.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<CanonicalisingActionsValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        const string inputWire =
            """[{"type":"payment_initiation","actions":["initiate","Initiate","INITIATE"]}]""";
        var raw = (JsonArray)JsonNode.Parse(inputWire)!;

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        var wire = validated!.ToJsonString();
        // Single-element arrays collapse to a string per the OAuth single-or-array
        // convention (see AuthorizationDetail.SetArrayOrStringOrNull).
        Assert.Contains("\"actions\":\"initiate\"", wire);
    }

    [Fact]
    public async Task ApplyAsync_forwards_byte_exact_when_dispatch_succeeds()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        const string wire = """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        var raw = (JsonArray)JsonNode.Parse(wire)!;

        var result = await composite.ApplyAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
        Assert.Equal(wire, validated!.ToJsonString());
    }

    [Fact]
    public async Task ApplyGrantedAsync_without_an_override_asks_the_request_time_question()
    {
        // The granted phase is a distinct question, not a weaker one: a type that does not enrich
        // answers the same way in both phases, so the anti-escalation re-check keeps biting for
        // every validator written before this member existed.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<RejectingValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var raw = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await composite.ApplyGrantedAsync(raw, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains(RejectingValidator.Reason, error.ErrorDescription);
    }

    [Fact]
    public async Task ApplyGrantedAsync_uses_the_overridden_granted_phase()
    {
        // RFC 9396 §7.1 enrichment: the same entry that must be refused from a client is the one the
        // consent decision produces, so the two phases have to be able to disagree.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<EnrichableAccountValidator>("account_information"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var enriched = new JsonArray(new JsonObject
        {
            ["type"] = "account_information",
            ["access"] = new JsonObject
            {
                ["accounts"] = new JsonArray(new JsonObject { ["iban"] = "DE2310010010123456789" }),
            },
        });

        var asRequest = await composite.ApplyAsync(
            (JsonArray)enriched.DeepClone(), TestClient, TestContext.Current.CancellationToken);
        var asGranted = await composite.ApplyGrantedAsync(
            enriched, TestClient, TestContext.Current.CancellationToken);

        Assert.True(asRequest.TryGetFailure(out _));
        Assert.True(asGranted.TryGetSuccess(out var validated));
        Assert.NotNull(validated);
    }

    [Theory]
    [InlineData("allowlist")]
    [InlineData("empty-allowlist")]
    [InlineData("unknown-type")]
    [InlineData("missing-type")]
    [InlineData("not-an-object")]
    public async Task ApplyGrantedAsync_keeps_every_check_outside_the_per_type_question(string shape)
    {
        // The granted phase changes ONE question. The claim that everything around it still binds is
        // otherwise carried by prose alone, and prose does not fail when an implementation stops
        // honouring it: a granted path that skipped these would take a type the client may not use,
        // a type nobody implements, or an entry that is not an object at all.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();

        var (client, granted, expected) = shape switch
        {
            "allowlist" => (
                new ClientInfo("c") { AuthorizationDetailsTypes = ["account_information"] },
                new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
                "payment_initiation"),
            "empty-allowlist" => (
                new ClientInfo("c") { AuthorizationDetailsTypes = [] },
                new JsonArray(new JsonObject { ["type"] = "payment_initiation" }),
                "not permitted"),
            "unknown-type" => (
                new ClientInfo("c"),
                new JsonArray(new JsonObject { ["type"] = "never_registered" }),
                "unknown"),
            "missing-type" => (
                new ClientInfo("c"),
                new JsonArray(new JsonObject { ["amount"] = "999999" }),
                "type"),
            "not-an-object" => (
                new ClientInfo("c"),
                new JsonArray(JsonValue.Create("payment_initiation")),
                "JSON object"),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "unhandled shape"),
        };

        var result = await composite.ApplyGrantedAsync(granted, client, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
        Assert.Contains(expected, error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ApplyGrantedAsync_falls_back_to_ApplyAsync_when_a_policy_does_not_override_it()
    {
        // The default member is what makes this addition non-breaking, and the shipped composite
        // overrides it - so nothing would notice if the default stopped deferring and started
        // accepting everything. A host that implements the interface itself is the case it protects.
        IAuthorizationDetailsPolicy policy = new RefusingPolicy();

        var granted = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });

        var result = await policy.ApplyGrantedAsync(granted, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(RefusingPolicy.Reason, error.ErrorDescription);

        // Forwarded, not merely reached: a default that called ApplyAsync with nothing would take the
        // "no entries" exit and answer success for every granted set, and a policy that ignores its
        // arguments cannot tell the two apart.
        var refusing = (RefusingPolicy)policy;
        Assert.Same(granted, refusing.LastRaw);
        Assert.Same(TestClient, refusing.LastClient);
    }

    [Fact]
    public async Task ApplyGrantedAsync_still_applies_the_rules_the_type_did_not_exempt()
    {
        // An enrichable type exempts the field the server fills in, and nothing else. Its other rules
        // hold against a consent decision exactly as they hold against a client.
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<EnrichableAccountValidator>("account_information"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsPolicy>();
        var granted = new JsonArray(new JsonObject { ["type"] = "account_information" });

        var result = await composite.ApplyGrantedAsync(granted, TestClient, TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("access is required", error.ErrorDescription);
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? registerValidators = null)
    {
        var services = new ServiceCollection();
        services.AddRichAuthorizationRequests();
        registerValidators?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private sealed class StubValidator(string? type = null) : IAuthorizationDetailValidator
    {
        public string Type => type ?? "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    private sealed class PaymentValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    private sealed class AccountValidator : IAuthorizationDetailValidator
    {
        public string Type => "account_information";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    private sealed class RejectingValidator : IAuthorizationDetailValidator
    {
        public const string Reason = "stub rejection from RejectingValidator";

        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, Reason));
    }

    /// <summary>
    /// An enrichable type, in the shape of RFC 9396 §7.1 Figures 16 and 17: the client sends empty
    /// placeholders, and the server writes the identifiers the user picked into them.
    /// </summary>
    private sealed class EnrichableAccountValidator : IAuthorizationDetailValidator
    {
        public string Type => "account_information";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult(
                detail.Json["access"]?["accounts"] is JsonArray { Count: > 0 }
                    ? Refuse("access.accounts is chosen by the end-user, so a request must leave it empty")
                    : SharedRules(detail));

        // Only the enrichable field is exempt here. Everything else the type refuses, it refuses in
        // both phases: a consent decision that crossed the browser is not more trusted than a client.
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

    /// <summary>
    /// A host's own policy: it implements the interface and knows nothing of the granted phase, which
    /// is the shape the default member exists for.
    /// </summary>
    private sealed class RefusingPolicy : IAuthorizationDetailsPolicy
    {
        public const string Reason = "refused by the host's own policy";

        public JsonArray? LastRaw { get; private set; }

        public ClientInfo? LastClient { get; private set; }

        public Task<Result<JsonArray?, OidcError>> ApplyAsync(
            JsonArray? raw, ClientInfo client, CancellationToken token)
        {
            LastRaw = raw;
            LastClient = client;

            return Task.FromResult<Result<JsonArray?, OidcError>>(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, Reason));
        }
    }

    private sealed class InvocationCounter
    {
        public int Count { get; private set; }
        public void Increment() => Count++;
    }

    /// <summary>Scenario 1: narrow amount 500 -> 200 to model a consent-UI slider.</summary>
    private sealed class NarrowToTwoHundredValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
        {
            if (detail.Json["instructedAmount"] is JsonObject amount)
                amount["amount"] = "200.00";
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
        }
    }

    /// <summary>Scenario 2: enforce a per-transaction client-tier cap of 1000.</summary>
    private sealed class TierCap1000Validator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
        {
            if (detail.Json["instructedAmount"] is JsonObject amount
                && amount["amount"]?.GetValue<string>() is { } amountStr
                && decimal.TryParse(amountStr, System.Globalization.NumberStyles.Any,
                    System.Globalization.CultureInfo.InvariantCulture, out var value)
                && value > 1000m)
            {
                amount["amount"] = "1000.00";
            }
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
        }
    }

    /// <summary>Scenario 4: dedupe + lowercase actions for canonical output.</summary>
    private sealed class CanonicalisingActionsValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
        {
            if (detail.Actions is { } actions)
            {
                detail.Actions = actions
                    .Select(a => a.ToLowerInvariant())
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
            }
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
        }
    }

    private sealed class CountingValidator(InvocationCounter counter) : IAuthorizationDetailValidator
    {
        public string Type => "account_information";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail,
            ClientInfo client,
            CancellationToken token)
        {
            counter.Increment();
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
        }
    }

    // ───────────────────────────────────────────────────────────────────────
    // BuildConsentDescriptorAsync - default interface method on the validator
    // returns null (#142 acceptance: hosts that opt out fall back to JSON
    // dump). Validators that opt in override and supply a structured shape.
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task BuildConsentDescriptorAsync_default_implementation_returns_null()
    {
        IAuthorizationDetailValidator validator = new StubValidator();
        var detail = new AuthorizationDetail(new JsonObject()) { Type = "payment_initiation" };

        var descriptor = await validator.BuildConsentDescriptorAsync(detail, TestClient, TestContext.Current.CancellationToken);

        Assert.Null(descriptor);
    }

    [Fact]
    public async Task BuildConsentDescriptorAsync_override_returns_descriptor_with_title_and_summary()
    {
        IAuthorizationDetailValidator validator = new DescribingValidator();
        var detail = new AuthorizationDetail(new JsonObject()) { Type = "payment_initiation" };

        var descriptor = await validator.BuildConsentDescriptorAsync(detail, TestClient, TestContext.Current.CancellationToken);

        Assert.NotNull(descriptor);
        Assert.Equal("Payment transfer", descriptor!.Title);
        Assert.Equal("Transfer 500 EUR to IBAN DE02 ...", descriptor.Summary);
        Assert.NotNull(descriptor.Details);
        Assert.Contains(descriptor.Details!,
            kv => kv.Key == "Amount" && kv.Value == "500.00 EUR");
    }

    private sealed class DescribingValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);

        public Task<AuthorizationDetailDescriptor?> BuildConsentDescriptorAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken cancellationToken)
            => Task.FromResult<AuthorizationDetailDescriptor?>(new AuthorizationDetailDescriptor(
                Title: "Payment transfer",
                Summary: "Transfer 500 EUR to IBAN DE02 ...",
                Details:
                [
                    new KeyValuePair<string, string>("Amount", "500.00 EUR"),
                    new KeyValuePair<string, string>("Beneficiary IBAN", "DE02 ..."),
                ]));
    }
}
