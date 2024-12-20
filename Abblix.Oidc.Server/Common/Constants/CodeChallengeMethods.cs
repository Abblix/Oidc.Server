﻿// Abblix OIDC Server Library
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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Static class representing the methods for PKCE (Proof Key for Code Exchange) code challenges.
/// </summary>
public static class CodeChallengeMethods
{
	/// <summary>
	/// Represents the "plain" code challenge method where the code verifier is sent without hashing.
	/// </summary>
	public const string Plain = "plain";

	/// <summary>
	/// Represents the "S256" code challenge method where the code verifier is hashed using SHA-256.
	/// </summary>
	public const string S256 = "S256";

	/// <summary>
	/// Represents the "S512" code challenge method where the code verifier is hashed using SHA-512.
	/// This method provides a higher level of security through a stronger hashing algorithm.
	/// </summary>
	public const string S512 = "S512";
}
