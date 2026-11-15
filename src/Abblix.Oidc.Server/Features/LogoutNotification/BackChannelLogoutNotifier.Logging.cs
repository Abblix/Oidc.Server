// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

partial class BackChannelLogoutNotifier
{
	[LoggerMessage(
		EventId = LogEvents.LogoutNotification.BackChannelLogoutNotifier.LogoutTokenNotIssued,
		Message = "No back-channel logout notification sent to client {ClientId}: {Reason}")]
	private partial void LogLogoutTokenNotIssued(LogLevel level, string ClientId, string Reason);
}
