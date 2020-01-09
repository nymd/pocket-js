import { Node } from "..";

/**
 *
 *
 * @class QueryNodeResponse
 */
export class QueryNodeResponse {
    /**
   *
   * Creates a QueryNodeResponse object using a JSON string
   * @param {String} json - JSON string.
   * @returns {QueryNodeResponse} - QueryNodeResponse object.
   * @memberof QueryNodeResponse
   */
    public static fromJSON(json: string): QueryNodeResponse {
        const jsonObject = JSON.parse(json);

        return new QueryNodeResponse(
            Node.fromJSON(jsonObject.node)
        );
    }

    public readonly node: Node;

    /**
     * Relay Response.
     * @constructor
     * @param {Node} node - Node object.
     */
    constructor(
        node: Node
    ) {
        this.node = node

        if (!this.isValid()) {
            throw new TypeError("Invalid properties length.");
        }
    }
    /**
   *
   * Creates a JSON object with the QueryNodeResponse properties
   * @returns {JSON} - JSON Object.
   * @memberof QueryNodeResponse
   */
    public toJSON() {
        return {"Node": this.node.toJSON()}
    }
    /**
   *
   * Check if the QueryNodeResponse object is valid
   * @returns {boolean} - True or false.
   * @memberof QueryNodeResponse
   */
    public isValid(): boolean {
        return this.node.isValid();
    }
}