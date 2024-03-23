// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
