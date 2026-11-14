// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// How a <see cref="TokenTypePolicy"/> judges the <c>typ</c> header of a token.
/// </summary>
public enum TokenTypeRule
{
	/// <summary>
	/// The token names one of the expected types.
	/// </summary>
	Exactly,

	/// <summary>
	/// The token names one of the expected types or names none.
	/// </summary>
	OrUntyped,

	/// <summary>
	/// The validator leaves the type to its caller, which judges it after validation.
	/// </summary>
	CheckedByCaller,
}
