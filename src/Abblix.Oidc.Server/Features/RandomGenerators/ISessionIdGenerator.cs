// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
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
