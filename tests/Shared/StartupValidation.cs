// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Tests.Shared;

/// <summary>
/// Runs what <c>ValidateOnStart</c> registered, as the host does before it starts. .NET 11 registers an
/// asynchronous validator; .NET 10 has only the synchronous one, and its failure is moved into the returned task
/// so a test awaiting a refusal reads the same on both frameworks.
/// </summary>
internal static class StartupValidation
{
    public static Task ValidateStartupAsync(this IServiceProvider services, CancellationToken cancellationToken)
#if NET11_0_OR_GREATER
        => services.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(cancellationToken);
#else
        => Task.Run(() => services.GetRequiredService<IStartupValidator>().Validate(), cancellationToken);
#endif
}
