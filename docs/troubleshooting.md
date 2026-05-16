# Troubleshooting

## Program hangs or runs too long

- Use `--timeout` to bound long attacks.
- Prefer targeted attacks with `--attack` when you know the likely family.

## `RsaRustTool` command not found

- Ensure binary exists: `target/release/RsaRustTool`
- Add symlink:

```bash
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool
```

- Ensure `~/.local/bin` is in `PATH`.

## Panic/backtrace debugging

Run with backtrace enabled:

```bash
RUST_BACKTRACE=1 RsaRustTool --publickey key.pub --private
```

Then open an issue with:

- command used
- input key type/size
- full panic/backtrace text
