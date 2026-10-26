# Protocol reference and attribution

This implementation is based on the Oura interoperability research and MIT
licensed code in [Th0rgal/open_oura](https://github.com/Th0rgal/open_oura), pinned
to commit `e57c43ce5fe0cf9a646afa790bda3731be767507`.

The reference supplies GATT identifiers, request layouts, authentication flow,
Ring 3/4/5 event formats, and captured test vectors. The Zig implementation uses
bounded buffers and caller-owned transport/storage. It does not include Oura
model weights, firmware, private keys, or proprietary mobile binaries.

Oura is a trademark of Oura. This independent project is not endorsed by Oura.

The following license applies to portions adapted from open_oura:

MIT License

Copyright (c) 2026 Thomas Marchand

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
