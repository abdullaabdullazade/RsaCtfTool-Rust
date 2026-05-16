# CLI Reference

## Common Usage

```bash
# Factor a key
RsaRustTool --publickey key.pub --private

# Use specific attacks
RsaRustTool --publickey key.pub --attack fermat,wiener --private

# Decrypt inline ciphertext
RsaRustTool --publickey key.pub --decrypt <hex_or_int> --private

# Decrypt ciphertext file
RsaRustTool --publickey key.pub --decryptfile cipher.bin --private

# Print key parameters
RsaRustTool --publickey key.pub --dumpkey
```

## Core Flags

- `--publickey` public key file path (wildcards supported)
- `--attack` comma-separated attack names
- `--timeout` per-attack timeout in seconds
- `--private` print recovered private key
- `--decrypt` decrypt inline ciphertext
- `--decryptfile` decrypt ciphertext from file
- `--dumpkey` print key details
- `-j, --threads` rayon thread count

For the full and up-to-date flag list, run:

```bash
RsaRustTool --help
```
