// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

/// <summary>
/// Represents an interface for creating a response to build the content of an OpenID Connect check-session frame (OP frame).
/// This interface defines a method for asynchronously processing the check session request and generating a response.
/// </summary>
public interface ICheckSessionHandler
{
	/// <summary>
	/// Asynchronously processes the check session request and generates a response containing the content of the OP check-session frame.
	/// </summary>
	/// <returns>A task representing the response, which includes the HTML content of the check-session frame.</returns>
	Task<CheckSessionResponse> HandleAsync();
}
