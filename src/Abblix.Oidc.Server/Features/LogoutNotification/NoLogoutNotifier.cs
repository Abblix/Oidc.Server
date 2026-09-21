// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// The member a deployment that serves no logout channel is left with: it notifies nobody and reports
/// every channel as unsupported, so the discovery document describes that deployment rather than the library.
/// </summary>
/// <remarks>
/// Each logout channel is the host's own choice, so the family may hold no channel at all. An empty family
/// composes to nothing, and everything resolving <see cref="ILogoutNotifier"/> - the configuration endpoint
/// among them - would then fail to resolve instead of answering that no channel is served. This member keeps
/// the family non-empty, and contributes no support to the composite, which reports a channel as supported
/// when any member does.
/// </remarks>
public class NoLogoutNotifier : ILogoutNotifier
{
    /// <inheritdoc />
    public Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext) => Task.CompletedTask;

    /// <inheritdoc />
    public bool FrontChannelLogoutSupported => false;

    /// <inheritdoc />
    public bool FrontChannelLogoutSessionSupported => false;

    /// <inheritdoc />
    public bool BackChannelLogoutSupported => false;

    /// <inheritdoc />
    public bool BackChannelLogoutSessionSupported => false;
}
