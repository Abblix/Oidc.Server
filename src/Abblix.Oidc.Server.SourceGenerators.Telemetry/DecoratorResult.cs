// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.SourceGenerators.Telemetry;

/// <summary>
/// What one entry of the list generates, with where the entry is written, so a later entry naming the same decorator
/// can be refused at its own place.
/// </summary>
/// <param name="Service">The handler the entry names.</param>
/// <param name="ClassName">The name of the decorator the entry generates.</param>
/// <param name="Result">The decorator's source, or the diagnostics refusing it.</param>
/// <param name="Location">Where the entry is written.</param>
internal sealed record DecoratorResult(string Service, string ClassName, GenerationResult Result, LocationInfo Location);
