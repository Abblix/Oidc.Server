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

namespace Abblix.Utils;

/// <summary>
/// Provides a static method for converting a byte array to its hexadecimal string representation.
/// </summary>
public static class HexConverter
{
	/// <summary>
	/// Converts a byte array to a hexadecimal string representation.
	/// </summary>
	/// <param name="bytes">The byte array to convert.</param>
	/// <returns>A string representing the hexadecimal representation of the byte array.</returns>
	public static string ToHexString(this byte[] bytes) => Convert.ToHexString(bytes);
}
