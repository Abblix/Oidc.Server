// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Spends what a grant is redeemed with only once (<see cref="AuthorizedGrant.Redemption"/>) once the processor it
/// wraps has answered the request with tokens, and refuses the request when another one has spent it.
/// </summary>
/// <remarks>
/// Spent after every validator of the token endpoint and after the processor, whose refusals (a resource the token
/// cannot be encrypted to, a scope narrowed to none) are as correctable as theirs, as the authorization code is spent
/// by <see cref="AuthorizationCodeReusePreventingDecorator"/>. The tokens of a request losing the spend are dropped
/// unseen.
/// </remarks>
/// <param name="processor">The processor issuing the tokens.</param>
internal sealed class SingleUseRedemptionDecorator(ITokenRequestProcessor processor) : ITokenRequestProcessor
{
	/// <inheritdoc />
	public async Task<Result<TokenIssued, OidcError>> ProcessAsync(TenantDefinition tenant, ValidTokenRequest request)
	{
		var result = await processor.ProcessAsync(tenant, request);

		if (result.TryGetSuccess(out _) &&
			request.AuthorizedGrant.Redemption is { } redemption &&
			await redemption.SpendAsync(tenant, request.ClientInfo) is { } spent)
		{
			return spent;
		}

		return result;
	}
}
