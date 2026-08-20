// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

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
/// <c>actions</c> non-empty and <c>instructedAmount</c> object present.
/// Anything richer is the host's concern at production time.
/// </summary>
public sealed class PaymentInitiationValidator : IAuthorizationDetailValidator
{
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

        if (detail.Json["instructedAmount"] is null)
        {
            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(
                new OidcError(ErrorCodes.InvalidAuthorizationDetails, "payment_initiation requires instructedAmount."));
        }

        return Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }
}
