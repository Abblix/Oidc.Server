// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.AuthorizationDetails;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Locks <see cref="AuthorizationDetailsTypesValidator"/> against the registration-time gap
/// it closes: client registration with an <c>authorization_details_types</c> entry the
/// server does not support must surface <c>invalid_client_metadata</c>, rather than
/// silently accepting and failing every later RAR request with
/// <c>invalid_authorization_details</c>.
/// </summary>
public class AuthorizationDetailsTypesValidatorTests
{
    private static AuthorizationDetailsTypesValidator Validator(params string[] supportedTypes)
    {
        var services = new ServiceCollection();
        foreach (var type in supportedTypes)
        {
            // Factory-based registration so the StubValidator instance knows its keyed-DI key
            // (and therefore reports a matching Type via the IAuthorizationDetailValidator
            // contract that discovery and metadata projection rely on).
            services.AddKeyedSingleton<IAuthorizationDetailValidator>(
                type,
                (_, key) => new StubValidator((string)key!));
        }
        return new AuthorizationDetailsTypesValidator(services.BuildServiceProvider());
    }

    private static ClientRegistrationValidationContext Context(string[]? authorizationDetailsTypes)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            AuthorizationDetailsTypes = authorizationDetailsTypes,
        });

    [Fact]
    public async Task ValidateAsync_NullAuthorizationDetailsTypes_Passes()
    {
        var validator = Validator();

        var result = await validator.ValidateAsync(Context(null));

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_EmptyAuthorizationDetailsTypes_PassesAsOptOut()
    {
        var validator = Validator("payment_initiation");

        var result = await validator.ValidateAsync(Context([]));

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_AllRequestedTypesAreSupported_Passes()
    {
        var validator = Validator("payment_initiation", "account_information");

        var result = await validator.ValidateAsync(Context(["payment_initiation"]));

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_OneRequestedTypeUnsupported_Rejects()
    {
        var validator = Validator("payment_initiation");

        var result = await validator.ValidateAsync(Context(["payment_initiation", "unknown_type"]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("unknown_type", result.ErrorDescription);
        Assert.DoesNotContain("payment_initiation", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_ZeroValidatorsRegistered_RejectsAnyNonEmptyRequest()
    {
        var validator = Validator();

        var result = await validator.ValidateAsync(Context(["payment_initiation"]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("payment_initiation", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_MultipleUnsupported_AllListedInError()
    {
        var validator = Validator("payment_initiation");

        var result = await validator.ValidateAsync(Context(["unknown_a", "unknown_b"]));

        Assert.NotNull(result);
        Assert.Contains("unknown_a", result.ErrorDescription);
        Assert.Contains("unknown_b", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_DuplicateUnsupported_DeduplicatedInError()
    {
        var validator = Validator("payment_initiation");

        var result = await validator.ValidateAsync(Context(["unknown_type", "unknown_type"]));

        Assert.NotNull(result);
        var firstIndex = result.ErrorDescription.IndexOf("unknown_type", StringComparison.Ordinal);
        var lastIndex = result.ErrorDescription.LastIndexOf("unknown_type", StringComparison.Ordinal);
        Assert.Equal(firstIndex, lastIndex);
    }

    private sealed class StubValidator(string? key = null) : IAuthorizationDetailValidator
    {
        public string Type => key ?? "stub";

        public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken ct)
            => Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
    }
}
