// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com


namespace Abblix.Oidc.Client.Features.SessionManagement;

/// <summary>
/// How this application watches the session at the provider.
/// </summary>
public sealed class SessionCheckOptions
{
    /// <summary>
    /// How often the frame asks the provider whether the login state has changed.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Session Management 1.0 section 3.1 leaves it open, saying the frame "polls the OP
    /// iframe with postMessage at an interval suitable for the RP application". The default is a compromise
    /// nobody should keep without thinking about it: often enough that a sign-out elsewhere is noticed while
    /// the user is still looking at the page, seldom enough that an idle tab is not asking every second.
    /// The cost of asking is one postMessage between two frames in the same browser - no network - so a
    /// shorter interval is cheaper than it looks.
    /// </remarks>
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(5);
}
