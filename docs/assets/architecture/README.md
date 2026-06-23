# Architecture Asset Notes

Rendered SVG diagrams and editable Mermaid source diagrams are both kept in the repository.

The SVG files are used by Markdown pages so architecture and flow diagrams remain visible in GitHub, IDE previews and documentation viewers that do not render `.mmd` files directly.

Rendered assets:

- `high-level-architecture.svg`
- `ingestion-correlation-pipeline.svg`
- `ai-capabilities-flow.svg`
- `local-first-sovereignty-architecture.svg`
- `deployment-architecture.svg`

Editable sources:

- `../../diagrams/high-level-architecture.mmd`
- `../../diagrams/ingestion-correlation-pipeline.mmd`
- `../../diagrams/ai-capabilities-flow.mmd`
- `../../diagrams/local-first-sovereignty-architecture.mmd`
- `../../diagrams/deployment-architecture.mmd`

The Mermaid files describe the editable topology for the current v0.7
architecture. The SVG files are curated hand-rendered assets that preserve the
project visual style: dark background, compact cards, color-coded domains and
accessible title/description metadata. When changing a diagram, keep the
Mermaid topology and the styled SVG rendering aligned.
