// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Represents the state of user consents in an authorization flow, categorizing them into granted, denied, and pending.
/// </summary>
public record UserConsents
{
    /// <summary>
    /// The consents that have been explicitly granted by the user.
    /// These consents cover scopes and resources the user has agreed to provide access to.
    /// </summary>
    public ConsentDefinition Granted { get; set; } = new(
        [],
        []);

    /// <summary>
    /// The consents that are still pending a decision by the user.
    /// These include scopes and resources that have been requested but not yet explicitly approved or denied.
    /// </summary>
    public ConsentDefinition Pending { get; set; } = new(
        [],
        []);
};
