# @vocdoni/poseidon377js

Poseidon hash implementation optimized for the **BLS12-377** curve.

## Installation

```bash
npm install @vocdoni/poseidon377js
```

## Usage

```typescript
import { buildPoseidon } from "@vocdoni/poseidon377js";

async function main() {
    const poseidon = await buildPoseidon();
    
    // Hash a chunk of elements (max rate 7)
    const h = poseidon.hash([1, 2, 3], 0);
    console.log(poseidon.F.toString(h, 10));

    // Multi-hash a list of elements (tree structure)
    const mh = poseidon.multiHash([1, 2, 3, 4, 5, 6, 7, 8, 9], 0);
    console.log(poseidon.F.toString(mh, 10));
}

main();
```

## Features

- Optimized for BLS12-377 scalar field.
- Supports rates from 1 to 7.
- Implements `multiHash` using a tree structure compatible with Circom templates.
- Fast execution using `ffjavascript` WASM-accelerated field arithmetic (from iden3).

## Development

```bash
npm install
npm test
npm run build
```
