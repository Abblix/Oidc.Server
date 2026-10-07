// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test validator for the RFC 9396 <c>payment_initiation</c> authorization-detail type.
/// Mirrors the PSD2-style payload shape used in the spec examples: requires
/// <c>actions</c> non-empty and <c>instructedAmount</c> object present, and holds a granted entry
/// to the requested ones the way a payment type would: the same currency and creditor account, and an
/// amount no higher. Anything richer is the host's concern at production time.
/// </summary>
public sealed class PaymentInitiationValidator : IAuthorizationDetailValidator
{
    private const string InstructedAmount = "instructedAmount";

    public string Type => "payment_initiation";

    public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token)
    {
        if (detail.Actions is null || !detail.Actions.Any())
        {
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, "payment_initiation requires non-empty actions."));
        }

        if (detail.Json[InstructedAmount] is null)
        {
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, "payment_initiation requires instructedAmount."));
        }

        return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    /// <summary>
    /// A granted entry stands only if some requested entry covers it, since RFC 9396 section 6.1 leaves that
    /// comparison to the type. An entry breaking the type's own rules is no end user's answer but a fault in
    /// the consent provider, so it is thrown rather than returned.
    /// </summary>
    public async Task<Result<AuthorizationDetail, OidcError>> ValidateGrantedAsync(
        AuthorizationDetail detail,
        IReadOnlyList<AuthorizationDetail> requested,
        ClientInfo client,
        CancellationToken token)
    {
        var validated = await ValidateAsync(detail, client, token);
        if (validated.TryGetFailure(out var defect))
        {
            throw new InvalidOperationException(
                $"The consent provider granted a payment_initiation entry no end user could: {defect.ErrorDescription}");
        }

        if (!requested.Any(asked => Covers(asked, detail)))
        {
            return new OidcError(
                ErrorCodes.InvalidAuthorizationDetails,
                "payment_initiation grants more than was requested.");
        }

        return validated;
    }

    private static bool Covers(AuthorizationDetail asked, AuthorizationDetail granted)
        => SamePayee(asked, granted) && AmountWithin(asked, granted);

    private static bool SamePayee(AuthorizationDetail asked, AuthorizationDetail granted)
        => JsonNode.DeepEquals(asked.Json["creditorAccount"], granted.Json["creditorAccount"]) &&
           JsonNode.DeepEquals(asked.Json[InstructedAmount]?["currency"], granted.Json[InstructedAmount]?["currency"]);

    private static bool AmountWithin(AuthorizationDetail asked, AuthorizationDetail granted)
        => AmountOf(asked) is { } askedAmount && AmountOf(granted) is { } grantedAmount && grantedAmount <= askedAmount;

    // Compared as numbers: as text, "1000" sorts below "200"
    private static decimal? AmountOf(AuthorizationDetail detail)
        => decimal.TryParse(
            detail.Json[InstructedAmount]?["amount"]?.ToString(),
            NumberStyles.Number,
            CultureInfo.InvariantCulture,
            out var amount)
            ? amount
            : null;
}
