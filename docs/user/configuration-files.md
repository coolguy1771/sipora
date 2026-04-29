# Configuration files

## Example TOML

Per-binary example TOML files live under `examples/config/` in the repository:

- `sipora-proxy.example.toml`
- `sipora-b2bua.example.toml`
- `sipora-edge.example.toml`
- `sipora-lb.example.toml`
- `sipora-api.example.toml`

Copy and adapt them for your environment; do not commit production secrets.

## Discovery and overrides

- Default config stem is **`sipora`**: the process loads `sipora.toml` / `sipora.yaml` (or other supported extensions) from the working directory when present.
- Use **`--config`** or **`SIPORA_CONFIG`** for another stem (for example `prod` loads `prod.toml`) or an explicit path to a `.toml` / `.yaml` file.
- Override merged fields with **`SIPORA__*`** environment variables (nested segments use `__`). Precedence and section meanings are documented under [configuration](/configuration).
