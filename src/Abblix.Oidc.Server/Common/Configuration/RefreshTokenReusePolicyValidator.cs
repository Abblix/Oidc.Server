// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a configured client whose refresh token reuse policy is not one of the values the policy
/// defines.
/// </summary>
/// <remarks>
/// A configuration binder takes a number outside the defined values as it stands, so the client would pass startup
/// and fail the first token request that issues it a refresh token.
/// </remarks>
public sealed class RefreshTokenReusePolicyValidator : IValidateOptions<OidcOptions>
{
	/// <inheritdoc />
	public ValidateOptionsResult Validate(string? name, OidcOptions options)
	{
		var failures = (options.Clients ?? [])
			.Where(client => !Enum.IsDefined(client.RefreshToken.ReusePolicy))
			.Select(client =>
				$"The client '{client.ClientId}' has {nameof(RefreshTokenOptions.ReusePolicy)} " +
				$"{client.RefreshToken.ReusePolicy}, which is not one of " +
				$"{string.Join(", ", Enum.GetNames<RefreshTokenReusePolicy>())}.")
			.ToList();

		return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
	}
}
