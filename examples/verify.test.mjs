import { readFile } from "node:fs/promises";
import { verifyEntitlement } from "./verify.js";
const f=JSON.parse(await readFile(new URL("./fixture.json", import.meta.url),"utf8"));
if (!(await verifyEntitlement(f.public_key,f.entitlement))) throw new Error("signature verification failed");
console.log("PASS verify.js");
