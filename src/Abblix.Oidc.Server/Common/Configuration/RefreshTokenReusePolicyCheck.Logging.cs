// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Common.Configuration;

public sealed partial class RefreshTokenReusePolicyCheck
{
	[LoggerMessage(
		EventId = LogEvents.MultiTenancy.RefreshTokenReusePolicyCheck.ReuseNotFollowed,
		Level = LogLevel.Warning,
		Message = "The client {ClientId} of the tenant {TenantId} is a public client with refresh token reuse but " +
		          "without required DPoP, so each of its refresh tokens bound to no DPoP key rotates all the same")]
	private partial void LogReuseNotFollowed(string tenantId, string clientId);
}
