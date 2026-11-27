// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Tests.Shared;

/// <summary>
/// Registers a host's own service the way a <see cref="HostRegistration"/> names, so one test drives each order.
/// </summary>
internal static class HostRegistrationExtensions
{
    /// <summary>
    /// The registration to make before the library's.
    /// </summary>
    public static Action<IServiceCollection> Before<T>(this HostRegistration registration, T instance)
        where T : class
        => registration switch
        {
            HostRegistration.AddBefore => services => services.AddSingleton(instance),
            HostRegistration.AddAfter or HostRegistration.TryAddAfter => _ => { },
            _ => throw new ArgumentOutOfRangeException(nameof(registration), registration, null),
        };

    /// <summary>
    /// The registration to make after the library's.
    /// </summary>
    public static Action<IServiceCollection> After<T>(this HostRegistration registration, T instance)
        where T : class
        => registration switch
        {
            HostRegistration.AddAfter => services => services.AddSingleton(instance),
            HostRegistration.TryAddAfter => services => services.TryAddSingleton(instance),
            HostRegistration.AddBefore => _ => { },
            _ => throw new ArgumentOutOfRangeException(nameof(registration), registration, null),
        };
}
