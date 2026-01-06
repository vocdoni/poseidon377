import { expect } from "chai";
import { buildPoseidon } from "../src/index.js";

describe("Poseidon377", function () {
    let poseidon: any;

    before(async () => {
        poseidon = await buildPoseidon();
    });

    it("should match Penumbra test vectors", async () => {
        const domain = poseidon.domainFromLEBytes(Buffer.from("Penumbra_TestVec"));
        const inputs = [
            "7553885614632219548127688026174585776320152166623257619763178041781456016062",
            "2337838243217876174544784248400816541933405738836087430664765452605435675740",
            "4318449279293553393006719276941638490334729643330833590842693275258805886300",
            "2884734248868891876687246055367204388444877057000108043377667455104051576315",
            "5235431038142849831913898188189800916077016298531443239266169457588889298166",
            "66948599770858083122195578203282720327054804952637730715402418442993895152",
        ];
        const expected = [
            inputs[1],
            inputs[2],
            inputs[3],
            inputs[4],
            inputs[5],
            "6797655301930638258044003960605211404784492298673033525596396177265014216269",
        ];

        for (let i = 1; i <= 6; i++) {
            const h = poseidon.hash(inputs.slice(0, i), domain);
            expect(poseidon.F.toString(h, 10)).to.equal(expected[i - 1], `Hash${i} mismatch`);
        }
    });

    it("should test all rates (1-7)", async () => {
        for (let r = 1; r <= 7; r++) {
            const inputs = Array.from({ length: r }, (_, i) => i + 1);
            const h = poseidon.hash(inputs, 0);
            expect(h).to.not.be.undefined;
            expect(poseidon.F.toString(h, 10)).to.be.a('string');
        }
    });

    it("should match Go implementation for MultiHash (8 inputs)", async () => {
        const inputs = [1, 2, 3, 4, 5, 6, 7, 8];
        const hash = poseidon.multiHash(inputs, 0);
        const expected = "5764845866250656314303187921704945420217061658264314081928253972326618949319";
        expect(poseidon.F.toString(hash, 10)).to.equal(expected);
    });
});