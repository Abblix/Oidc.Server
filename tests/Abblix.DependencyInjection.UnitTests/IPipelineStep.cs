namespace Abblix.DependencyInjection.UnitTests;

/// <summary>Shared pipeline fixtures for the composed-family tests.</summary>
internal interface IPipelineStep
{
    string Name { get; }
}