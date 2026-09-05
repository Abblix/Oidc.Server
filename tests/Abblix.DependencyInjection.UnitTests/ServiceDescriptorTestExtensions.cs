// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Reflection-based stand-in for the internal-in-.NET
/// <c>ServiceDescriptor.GetImplementationType()</c>, used by tests that assert on the
/// dedup key <c>TryAddEnumerable</c> compares.
/// </summary>
internal static class ServiceDescriptorTestExtensions
{
    public static Type? GetImplementationTypeOrDefault(this ServiceDescriptor d)
    {
        if (d.ImplementationType != null) return d.ImplementationType;
        if (d.ImplementationInstance != null) return d.ImplementationInstance.GetType();
        if (d.ImplementationFactory != null)
        {
            var args = d.ImplementationFactory.GetType().GetGenericArguments();
            if (args.Length == 2) return args[1];
        }
        return null;
    }
}