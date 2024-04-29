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

using Microsoft.IdentityModel.Tokens;



namespace Abblix.Jwt;

/// <summary>
/// Provides functionality to map signing algorithm names to their corresponding outbound algorithm names.
/// </summary>
public static class AlgorithmMapper
{
	/// <summary>
	/// Maps a given signing algorithm name to the corresponding outbound algorithm name.
	/// </summary>
	/// <param name="signingAlgorithm">The signing algorithm name to map.</param>
	/// <returns>The outbound algorithm name corresponding to the given signing algorithm.</returns>
	/// <remarks>
	/// This mapping is used to standardize algorithm names across different contexts or specifications,
	/// ensuring consistency in cryptographic operations.
	/// </remarks>
	public static string MapToOutbound(string signingAlgorithm) => signingAlgorithm switch
	{
		SecurityAlgorithms.EcdsaSha256Signature => SecurityAlgorithms.EcdsaSha256,
		SecurityAlgorithms.EcdsaSha384Signature => SecurityAlgorithms.EcdsaSha384,
		SecurityAlgorithms.EcdsaSha512Signature => SecurityAlgorithms.EcdsaSha512,

		SecurityAlgorithms.HmacSha256Signature => SecurityAlgorithms.HmacSha256,
		SecurityAlgorithms.HmacSha384Signature => SecurityAlgorithms.HmacSha384,
		SecurityAlgorithms.HmacSha512Signature => SecurityAlgorithms.HmacSha512,

		SecurityAlgorithms.RsaSha256Signature => SecurityAlgorithms.RsaSha256,
		SecurityAlgorithms.RsaSha384Signature => SecurityAlgorithms.RsaSha384,
		SecurityAlgorithms.RsaSha512Signature => SecurityAlgorithms.RsaSha512,

		SecurityAlgorithms.Aes128KeyWrap => SecurityAlgorithms.Aes128KW,
		SecurityAlgorithms.Aes192KeyWrap => SecurityAlgorithms.Aes256KW,
		SecurityAlgorithms.RsaV15KeyWrap => SecurityAlgorithms.RsaPKCS1,
		SecurityAlgorithms.RsaOaepKeyWrap => SecurityAlgorithms.RsaOAEP,

		_ => signingAlgorithm,
	};
}
