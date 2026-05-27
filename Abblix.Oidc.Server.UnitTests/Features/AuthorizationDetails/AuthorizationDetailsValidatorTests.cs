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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.AuthorizationDetails;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.AuthorizationDetails;

/// <summary>
/// Unit tests for the composite <see cref="IAuthorizationDetailsValidator"/> registered via
/// <c>AddRichAuthorizationRequests()</c>. Covers dispatch by <c>type</c>, RFC 9396 §5 unknown-type
/// rejection, per-type-validator failure propagation, and the graceful-degradation contract
/// (server boots cleanly with zero per-type validators registered).
/// </summary>
public class AuthorizationDetailsValidatorTests
{
    private static readonly ClientInfo TestClient = new("test-client");

    [Fact]
    public void Composite_resolves_with_zero_per_type_validators_registered()
    {
        var sp = BuildProvider();

        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();

        Assert.NotNull(composite);
    }

    [Fact]
    public async Task Unknown_type_yields_invalid_authorization_details_failure()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "payment_initiation" },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("payment_initiation", error.Description);
        Assert.Contains("unknown", error.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Missing_type_member_yields_failure()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = null! },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("type", error.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Empty_details_array_yields_empty_validated_list()
    {
        var sp = BuildProvider();
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();

        var result = await composite.ValidateAsync([], TestClient, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.Empty(validated);
    }

    [Fact]
    public async Task Single_validator_dispatched_by_type_returns_validated_detail()
    {
        var sp = BuildProvider(registerValidators: services =>
            services.AddAuthorizationDetailValidator<StubValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "payment_initiation", Actions = ["initiate"] },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var validated));
        var item = Assert.Single(validated);
        Assert.Equal("payment_initiation", item.Type);
        Assert.Equal(new[] { "initiate" }, item.Actions);
    }

    [Fact]
    public async Task Multiple_validators_dispatched_in_order_on_success()
    {
        var sp = BuildProvider(registerValidators: services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation")
            .AddAuthorizationDetailValidator<AccountValidator>("account_information"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "payment_initiation" },
            new AuthorizationDetail { Type = "account_information" },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.Equal(2, validated.Count);
        Assert.Equal("payment_initiation", validated[0].Type);
        Assert.Equal("account_information", validated[1].Type);
    }

    [Fact]
    public async Task Per_type_validator_failure_propagates_through_composite()
    {
        var sp = BuildProvider(registerValidators: services =>
            services.AddAuthorizationDetailValidator<RejectingValidator>("payment_initiation"));
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "payment_initiation" },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(RejectingValidator.Reason, error.Description);
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
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "payment_initiation" },
            new AuthorizationDetail { Type = "account_information" },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

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
        var composite = sp.GetRequiredService<IAuthorizationDetailsValidator>();
        var details = new[]
        {
            new AuthorizationDetail { Type = "consent" },
            new AuthorizationDetail { Type = "payment_initiation" },
            new AuthorizationDetail { Type = "account_information" },
        };

        var result = await composite.ValidateAsync(details, TestClient, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.Equal(["consent", "payment_initiation", "account_information"],
            validated.Select(d => d.Type).ToArray());
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

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
            => Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
    }

    private sealed class PaymentValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
            => Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
    }

    private sealed class AccountValidator : IAuthorizationDetailValidator
    {
        public string Type => "account_information";

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
            => Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
    }

    private sealed class RejectingValidator : IAuthorizationDetailValidator
    {
        public const string Reason = "stub rejection from RejectingValidator";

        public string Type => "payment_initiation";

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
            => Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(
                new AuthorizationDetailValidationError(Reason));
    }

    private sealed class InvocationCounter
    {
        public int Count { get; private set; }
        public void Increment() => Count++;
    }

    private sealed class CountingValidator(InvocationCounter counter) : IAuthorizationDetailValidator
    {
        public string Type => "account_information";

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
        {
            counter.Increment();
            return Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
        }
    }
}
