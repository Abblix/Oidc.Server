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

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// What the <see cref="InsecureValidationGuard"/> needs to know about the profile it decorates:
/// which family to read and which allowances excuse a missing critical step.
/// </summary>
/// <param name="Key">The profile's service key.</param>
/// <param name="Allowances">The profile's own allowances - the only ones that can excuse it.</param>
internal sealed record ValidationProfileIdentity(object Key, IReadOnlyList<string> Allowances);
