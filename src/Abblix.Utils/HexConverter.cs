// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
