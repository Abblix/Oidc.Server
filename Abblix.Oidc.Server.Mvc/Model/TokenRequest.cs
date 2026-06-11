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

using Abblix.Oidc.Server.Mvc.Attributes;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// The transport-bound counterpart of <see cref="Core.TokenRequest"/> for the token endpoint.
/// All bound properties, model binders resolved from the core wire-format markers, validation
/// attributes and the projection back onto the core model are generated from the core type.
/// </summary>
[GeneratedFrom(typeof(Core.TokenRequest))]
public partial record TokenRequest;
