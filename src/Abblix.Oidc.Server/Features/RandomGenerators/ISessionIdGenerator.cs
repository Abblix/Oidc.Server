// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Defines the interface for generating new session identifiers, which are crucial for tracking user sessions
/// in web applications, especially in scenarios involving authentication and authorization processes.
/// </summary>
public interface ISessionIdGenerator
{
	/// <summary>
	/// Generates a new, unique session identifier. This method is responsible for producing session IDs that
	/// are sufficiently random and unique to securely identify individual user sessions. The generated IDs
	/// are used in session management mechanisms to differentiate between user sessions, thereby ensuring
	/// that user data and interactions are isolated and protected across different sessions.
	/// </summary>
	/// <returns>A new, unique session identifier as a string. The format and characteristics of the session ID
	/// (e.g., length, characters used) should be designed to enhance security and minimize the risk of session
	/// hijacking or collision.</returns>
	string GenerateSessionId();
}
