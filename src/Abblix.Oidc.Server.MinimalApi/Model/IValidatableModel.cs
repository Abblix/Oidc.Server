// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// Marks a generated request model that carries declarative validation rules. The source generator translates the
/// core model's declarative markers (<c>[AllowedValues]</c>, <c>[AbsoluteUri]</c>, <c>[ElementsRequired]</c>,
/// <c>[Required]</c>) into executable <see cref="System.ComponentModel.DataAnnotations.ValidationAttribute"/>s on the
/// bound model and adds this marker, so the group-scoped validation endpoint filter knows to run
/// <see cref="System.ComponentModel.DataAnnotations.Validator"/> over it and shape any failure as
/// <c>invalid_request</c>. A pure marker - the validation logic lives in the individual attributes, not here.
/// </summary>
internal interface IValidatableModel;
