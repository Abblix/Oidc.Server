// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

// ReSharper disable once CheckNamespace
namespace System.Runtime.CompilerServices;

/// <summary>
/// Compiler polyfill enabling C# records and init-only setters on netstandard2.0,
/// where the runtime does not ship this marker type.
/// </summary>
[SuppressMessage("Major Code Smell", "S2094:Classes should not be empty",
	Justification = "Compiler-required marker type; the compiler keys on its mere presence")]
internal static class IsExternalInit;
