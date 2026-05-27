// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.AuthorizationDetails;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test validator for the RFC 9396 <c>payment_initiation</c> authorization-detail type.
/// Mirrors the PSD2-style payload shape used in the spec examples: requires
/// <c>actions</c> non-empty and <c>instructedAmount</c> object present.
/// Anything richer is the host's concern at production time.
/// </summary>
public sealed class PaymentInitiationValidator : IAuthorizationDetailValidator
{
    public string Type => "payment_initiation";

    public Task<Result<AuthorizationDetail, AuthorizationDetailValidationError>> ValidateAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken ct)
    {
        if (detail.Actions is null || !detail.Actions.Any())
        {
            return Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(
                new AuthorizationDetailValidationError("payment_initiation requires non-empty actions."));
        }

        if (detail.Json["instructedAmount"] is null)
        {
            return Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(
                new AuthorizationDetailValidationError("payment_initiation requires instructedAmount."));
        }

        return Task.FromResult<Result<AuthorizationDetail, AuthorizationDetailValidationError>>(detail);
    }
}
