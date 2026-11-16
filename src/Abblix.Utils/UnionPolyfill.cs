// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

#if !NET11_0_OR_GREATER

namespace System.Runtime.CompilerServices;

/// <summary>
/// Marks a type as a union. The compiler emits it on every union declaration and looks it up by name, so
/// on a framework whose runtime library lacks it the declaration needs this copy.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
internal sealed class UnionAttribute : Attribute;

/// <summary>
/// The contained value of a union, which the compiler implements on every union declaration.
/// </summary>
internal interface IUnion
{
    /// <summary>
    /// The case value the union holds, or <c>null</c> when it holds none.
    /// </summary>
    object? Value { get; }
}

#endif
