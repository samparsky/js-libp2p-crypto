/// <reference path="../../src/types.d.ts" />
import generate from "libp2p-crypto/keys/key-stretcher";
const bootstrap1 = generate()
bootstrap1.start()