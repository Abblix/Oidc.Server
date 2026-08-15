namespace Abblix.DependencyInjection.UnitTests;

/// <summary>Wraps whatever answers <see cref="IPipelineStep"/>, so a test can decorate a composed family.</summary>
internal sealed class PipelineDecorator(IPipelineStep inner) : IPipelineStep
{
    public string Name => $"[{inner.Name}]";
}