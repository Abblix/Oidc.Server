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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents subject types used in OpenID Connect.
/// </summary>
public static class SubjectTypes
{
	/// <summary>
	/// The "public" subject type indicates that the subject identifier is a public identifier,
	/// which means that it can be used across multiple clients and should not be tied to a specific client.
	/// </summary>
	public const string Public = "public";

	/// <summary>
	/// The "pairwise" subject type indicates that the subject identifier is a pairwise identifier,
	/// which means that it is unique to a specific client, enhancing user privacy.
	/// </summary>
	public const string Pairwise = "pairwise";
}
