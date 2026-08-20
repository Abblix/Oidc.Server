// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


#if NET8_0

namespace System.Threading;

/// <summary>
/// Stands in for <c>System.Threading.Lock</c>, which arrived in .NET 9.
/// </summary>
/// <remarks>
/// Lets a single source file use the newer mutual-exclusion type across every target this library supports.
/// On .NET 9 and later the real type is used, and the compiler lowers <c>lock</c> on it to
/// <see cref="EnterScope"/>; on .NET 8 this stands in and the same statement lowers to <c>Monitor</c>, which
/// is what the code would have used anyway.
///
/// The shape mirrors the real type only as far as <c>lock</c> needs, because that is all this exists for:
/// nothing should take a dependency on a polyfill beyond the syntax it enables.
/// </remarks>
public sealed class Lock
{
    /// <summary>
    /// What Monitor actually locks on. The polyfill cannot pass itself, because the compiler recognises the
    /// name System.Threading.Lock and refuses monitor-based locking on it - the very confusion the real type
    /// exists to prevent.
    /// </summary>
    private readonly object _syncRoot = new();

    /// <summary>
    /// Enters the lock, returning a scope that leaves it when disposed.
    /// </summary>
    public Scope EnterScope()
    {
        Monitor.Enter(_syncRoot);
        return new Scope(_syncRoot);
    }

    /// <summary>
    /// The holder of an entered lock, which releases it when disposed.
    /// </summary>
    public ref struct Scope
    {
        private readonly object _syncRoot;

        internal Scope(object syncRoot) => _syncRoot = syncRoot;

        /// <summary>Leaves the lock.</summary>
        public void Dispose() => Monitor.Exit(_syncRoot);
    }
}

#endif
