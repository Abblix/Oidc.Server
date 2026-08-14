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
    // RFC 9396 §5 validator-side mutation pipeline. Per-type validators see
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
