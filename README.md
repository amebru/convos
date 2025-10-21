# convos

`convos` is a command-line browser for exported gen-AI conversations.
It auto-detects ChatGPT and Claude archive formats and renders conversations with
syntax-highlighted code blocks and lightweight UI chrome.

## Build & Install
- Compile an optimized binary:
  ```
  cargo build --release
  ```
- Find the executable at `target/release/convos`.
- Optional: Symlink it into a directory on your `PATH`, e.g.:
  ```
  ln target/release/convos ~/.local/bin/
  ```

## Usage
Run the reader with the path to an root of the raw exported chat directory:
```
convos /path/to/chatgpt-chatlogs/<chatgpt-export-directory-hash>...
```
```
convos /path/to/claude-chatlogs/data-...
```
The app shows a spinner while loading, lists conversations in reverse chronological
order, and lets you filter by typing. Press `q` at the search prompt to exit.
