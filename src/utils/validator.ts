import {ChallengeRequest} from "../rpc/models/input/challenge-request"
import {Hex} from "./hex"
import {RelayProof, RelayResponse, RelayMeta, RequestHash} from "../rpc/models"
import {typeGuard} from "./type-guard"
import {MajorityResponse} from "../rpc/models/input/majority-response"
import {validateAddressHex} from "./key-pair"
import { InMemoryKVStore } from "../storage/in-memory-kv-store"
import { Keybase } from "../keybase"
import { sha3_256 } from "js-sha3"


/**
 * Validates a ChallengeRequest
 * @param {ChallengeRequest} request - The ChallengeRequest to be evaluated.
 * @returns {Error | undefined}.
 */
export async function validateChallengeRequest(request: ChallengeRequest): Promise<Error | undefined> {
    switch (true) {
        case typeGuard(validateRelayResponse(request.minorityResponse.relay), Error):
            return await validateRelayResponse(request.minorityResponse.relay) as Error
        case request.majorityResponse.relays.length !== 2:
            return new Error("Invalid majority request. The amount of relays needs to be equals to 2")
        case typeGuard(validateMajorityResponse(request.majorityResponse), Error):
            return await validateMajorityResponse(request.majorityResponse) as Error
        default:
            return undefined
    }
}

/**
 * Validates a MajorityResponse
 * @param {MajorityResponse} response - The MajorityResponse to be evaluated.
 * @returns {Error | undefined}.
 */
export async function validateMajorityResponse(response: MajorityResponse): Promise<Error | undefined> {
    let result: Error | undefined
    response.relays.forEach(async (relay) =>  {
        result = await validateRelayResponse(relay)
    })
    return result
}

/**
 * Validates a Relay response
 * @param {RelayResponse} relay - The Relay response to be evaluated.
 * @returns {Error | undefined}.
 */
export async function validateRelayResponse(relay: RelayResponse): Promise<Error | undefined>{
    const keybase = new Keybase(new InMemoryKVStore())

    const hash = sha3_256.create()
    hash.update(JSON.stringify(relay.proof.toJSON()))

    const payload = Buffer.from(hash.hex(), "hex")
    const signerPubKeyBuffer = Buffer.from(relay.proof.servicerPubKey, "hex")
    const signature = Buffer.from(relay.signature, "hex")

    const isVerified = await keybase.verifySignature(signerPubKeyBuffer, payload, signature)
    switch (true) {
        
        // This should be a better check for validity
        case !Hex.isHex(relay.signature):
            return new Error("Invalid string is not hex: " + relay.signature)
        case !Hex.isHex(relay.signature):
            return new Error("Invalid string is not hex: " + relay.signature)
        default:
            return undefined
    }
}

/**
 * Validates a RelayProof
 * @param {RelayProof} proof - The RelayProof to be evaluated.
 * @returns {Error | undefined}.
 */
export function validateRelayProof(proof: RelayProof): Error | undefined  {
    switch (true) {
        case proof.blockchain.length === 0:
            return new Error("Invalid chain. The chain cannot be empty")
        case Number(proof.entropy.toString()) === undefined:
            return new Error("Invalid entropy. The entropy needs to be a number: " + proof.entropy)
        case !Hex.isHex(proof.signature):
            return new Error("Invalid string is not hex: " + proof.signature)
        case !Hex.isHex(proof.servicerPubKey):
            return new Error("Invalid string is not hex: " + proof.servicerPubKey)
        case Number(proof.sessionBlockHeight) === 0:
            return new Error("The Block Height needs to be bigger than 0")
        case !proof.token.isValid():
            return new Error("The token is invalid")
        default:
            return undefined
    }
}

