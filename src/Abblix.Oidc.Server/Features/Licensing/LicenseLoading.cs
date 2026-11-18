// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Completes once the licenses the host supplies are loaded, for whatever must judge against them at startup.
/// </summary>
/// <remarks>
/// The hosting starts its services one after another by default, yet a host may have them start at once, and then a
/// service registered after the one loading the licenses can run first and read the limits of an installation with no
/// license. Waiting for this does not depend on that order.
/// </remarks>
internal sealed class LicenseLoading
{
    private readonly TaskCompletionSource _loaded = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Completes when the licenses are loaded, and fails as the loading failed.
    /// </summary>
    public Task Loaded => _loaded.Task;

    /// <summary>
    /// Marks the licenses as loaded.
    /// </summary>
    public void Complete() => _loaded.TrySetResult();

    /// <summary>
    /// Marks the loading as failed with <paramref name="exception"/>.
    /// </summary>
    public void Fail(Exception exception) => _loaded.TrySetException(exception);
}
