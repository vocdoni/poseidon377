// @ts-ignore
import { buildBls12377 } from 'ffjavascript';
import * as constants from "./constants.js";

export class Poseidon377 {
    F: any;
    private mds: any[];
    private mi: any[] | null;
    private arc: any[];
    private v: any[];
    private w: any[];
    private m00: any;
    private rate: number;

    constructor(F: any, rate: number) {
        this.F = F;
        this.rate = rate;
        this.arc = constants.ARC[rate].map((x: string) => F.e(x));
        this.mds = constants.MDS[rate].map((x: string) => F.e(x));
        this.mi = constants.MI[rate] ? constants.MI[rate].map((x: string) => F.e(x)) : null;
        this.v = constants.SparseV[rate].map((x: string) => F.e(x));
        this.w = constants.SparseWHat[rate].map((x: string) => F.e(x));
        this.m00 = F.e(constants.M00[rate]);
    }

    private sbox(inVal: any) {
        const m2 = this.F.mul(inVal, inVal);
        const m4 = this.F.mul(m2, m2);
        const m8 = this.F.mul(m4, m4);
        const m16 = this.F.mul(m8, m8);
        return this.F.mul(m16, inVal);
    }

    private mix(state: any[]) {
        const t = state.length;
        const newState = new Array(t);
        for (let i = 0; i < t; i++) {
            let sum = this.F.zero;
            for (let j = 0; j < t; j++) {
                sum = this.F.add(sum, this.F.mul(this.mds[i * t + j], state[j]));
            }
            newState[i] = sum;
        }
        return newState;
    }

    private mixMI(state: any[]) {
        if (!this.mi) return this.mix(state);
        const t = state.length;
        const newState = new Array(t);
        for (let i = 0; i < t; i++) {
            let sum = this.F.zero;
            for (let j = 0; j < t; j++) {
                sum = this.F.add(sum, this.F.mul(this.mi[i * t + j], state[j]));
            }
            newState[i] = sum;
        }
        return newState;
    }

    private sparseMix(state: any[], round: number) {
        const t = state.length;
        const newState = new Array(t);
        const subSize = t - 1;
        const offset = round * subSize;

        let sum0 = this.F.mul(this.m00, state[0]);
        for (let i = 0; i < subSize; i++) {
            sum0 = this.F.add(sum0, this.F.mul(this.w[offset + i], state[i + 1]));
        }
        newState[0] = sum0;

        for (let i = 0; i < subSize; i++) {
            newState[i + 1] = this.F.add(this.F.mul(this.v[offset + i], state[0]), state[i + 1]);
        }
        return newState;
    }

    permutation(inState: any[]) {
        const t = this.rate + 1;
        let state = [...inState];
        const RF = constants.FULL_ROUNDS;
        const RP = constants.PARTIAL_ROUNDS;
        const rF_half = Math.floor(RF / 2);

        // First half full rounds
        for (let r = 0; r < rF_half; r++) {
            for (let i = 0; i < t; i++) {
                state[i] = this.sbox(this.F.add(state[i], this.arc[r * t + i]));
            }
            state = this.mix(state);
        }

        // First Partial Round (Dense Mix MI)
        const roundIdx = rF_half;
        for (let i = 0; i < t; i++) {
            state[i] = this.F.add(state[i], this.arc[roundIdx * t + i]);
        }
        state = this.mixMI(state);

        // Middle Partial Rounds (RP - 1 rounds)
        for (let r = 0; r < RP - 1; r++) {
            state[0] = this.sbox(state[0]);
            const constIdx = rF_half + 1 + r;
            state[0] = this.F.add(state[0], this.arc[constIdx * t]);
            
            const sparseRound = RP - r - 1;
            state = this.sparseMix(state, sparseRound);
        }

        // Final Partial Round
        state[0] = this.sbox(state[0]);
        state = this.sparseMix(state, 0);

        // Second half Full Rounds
        const roundFull2 = rF_half + RP;
        for (let r = 0; r < rF_half; r++) {
            const rConstIdx = roundFull2 + r;
            for (let i = 0; i < t; i++) {
                state[i] = this.sbox(this.F.add(state[i], this.arc[rConstIdx * t + i]));
            }
            state = this.mix(state);
        }

        return state;
    }

    hash(inputs: any[], domain: any = 0) {
        if (inputs.length !== this.rate) {
            throw new Error(`Expected ${this.rate} inputs, got ${inputs.length}`);
        }
        const t = this.rate + 1;
        const state = new Array(t);
        state[0] = this.F.e(domain);
        for (let i = 0; i < this.rate; i++) {
            state[i + 1] = this.F.e(inputs[i]);
        }
        const outState = this.permutation(state);
        return outState[1];
    }
}

export async function buildPoseidon(singleThread: boolean = false): Promise<{
    hash: (inputs: any[], domain?: any) => any;
    multiHash: (inputs: any[], domain?: any) => any;
    F: any;
    domainFromLEBytes: (data: Uint8Array) => any;
}> {
    const bls = await buildBls12377(singleThread);
    const F = bls.Fr;

    // Cache instances for each rate
    const instances: Record<number, Poseidon377> = {};
    for (let r = 1; r <= 7; r++) {
        instances[r] = new Poseidon377(F, r);
    }

    function hash(inputs: any[], domain: any = 0) {
        const rate = inputs.length;
        if (rate < 1 || rate > 7) {
            throw new Error(`Unsupported rate: ${rate}. Supported rates: 1-7`);
        }
        return instances[rate].hash(inputs, domain);
    }

    function multiHash(inputs: any[], domain: any = 0) {
        const maxRate = 7;
        if (inputs.length === 0) return F.zero;

        let currentLevel = inputs.map(x => F.e(x));
        const dom = F.e(domain);

        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += maxRate) {
                const chunk = currentLevel.slice(i, i + maxRate);
                nextLevel.push(hash(chunk, dom));
            }
            currentLevel = nextLevel;
        }

        // Final hash if only 1 input was provided initially
        if (inputs.length === 1) {
             return hash(inputs, dom);
        }

        return currentLevel[0];
    }

    function domainFromLEBytes(data: Uint8Array): any {
        let bi = 0n;
        for (let i = 0; i < data.length; i++) {
            bi += BigInt(data[i]) << BigInt(8 * i);
        }
        return F.e(bi);
    }

    return { hash, multiHash, F, domainFromLEBytes };
}