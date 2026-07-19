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

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// Marks a generated request model that carries declarative validation rules. The source generator translates the
/// core model's declarative markers (<c>[AllowedValues]</c>, <c>[AbsoluteUri]</c>, <c>[ElementsRequired]</c>,
/// <c>[Required]</c>) into executable <see cref="System.ComponentModel.DataAnnotations.ValidationAttribute"/>s on the
/// bound model and adds this marker, so the group-scoped validation endpoint filter knows to run
/// <see cref="System.ComponentModel.DataAnnotations.Validator"/> over it and shape any failure as
/// <c>invalid_request</c>. A pure marker — the validation logic lives in the individual attributes, not here.
/// </summary>
internal interface IValidatableModel;
